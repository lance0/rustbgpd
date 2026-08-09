use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
};

use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_policy::RouteType;
use rustbgpd_wire::{Afi, BgpRole, Safi};
use tempfile::NamedTempFile;

use crate::test_support::tier_authorized_uds_test_config;

const TEST_ONLY_GRPC_OPERATOR_PRINCIPAL: &str = "rustbgpd://operator/test-only";
const TEST_ONLY_GRPC_TOKEN_CONTAINER_PATH: &str = "/run/rustbgpd/grpc-test-only-operator.token";
const TEST_ONLY_GRPC_TOKEN_REPO_PATH: &str = "tests/fixtures/grpc-test-only-operator.token";

fn materialize_shared_test_only_grpc_token(source: &str) -> String {
    let host_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(TEST_ONLY_GRPC_TOKEN_REPO_PATH);
    assert!(
        host_path.is_file(),
        "shared test-only gRPC token fixture must exist at {}",
        host_path.display()
    );
    let host_path = host_path
        .to_str()
        .expect("repository test-token path must be UTF-8");
    source.replace(TEST_ONLY_GRPC_TOKEN_CONTAINER_PATH, host_path)
}

fn parse_with_shared_test_grpc_token(source: &str) -> Result<Config, ConfigError> {
    parse_strict(&materialize_shared_test_only_grpc_token(source))
}

fn valid_toml() -> &'static str {
    // Shared test fixture used by hundreds of config tests below.
    // `parse()` explicitly adds the canonical Tier-authorized UDS
    // identity before exercising the production validator.
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

/// Deserialize only, for tests of schema defaults and listener materialization
/// whose intentionally incomplete authentication is rejected by validation.
fn parse_schema_only(toml_str: &str) -> Result<Config, ConfigError> {
    toml::from_str(toml_str).map_err(ConfigError::Parse)
}

/// Test entry used by config tests that do not exercise the gRPC
/// authorization surface. The explicit helper keeps the fixture Tier-valid
/// without changing production loader input.
fn parse(toml_str: &str) -> Result<Config, ConfigError> {
    let tier_authorized = tier_authorized_uds_test_config(toml_str);
    let config: Config = toml::from_str(&tier_authorized).map_err(ConfigError::Parse)?;
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

fn route_server_example_config() -> Config {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/route-server/config.toml");
    Config::load_with_diagnostics(path.to_str().expect("route-server example path is UTF-8"))
        .expect("route-server example loads through the production config path")
}

fn route_server_test_prefix(value: &str) -> Prefix {
    let (address, length) = value
        .split_once('/')
        .unwrap_or_else(|| panic!("test prefix {value:?} has no length"));
    let length = length
        .parse::<u8>()
        .unwrap_or_else(|error| panic!("test prefix {value:?} has an invalid length: {error}"));
    match address
        .parse::<std::net::IpAddr>()
        .unwrap_or_else(|error| panic!("test prefix {value:?} has an invalid address: {error}"))
    {
        std::net::IpAddr::V4(address) => {
            assert!(length <= 32, "IPv4 test prefix {value:?} exceeds /32");
            Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(address, length))
        }
        std::net::IpAddr::V6(address) => {
            assert!(length <= 128, "IPv6 test prefix {value:?} exceeds /128");
            Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(address, length))
        }
    }
}

fn route_server_test_context(
    prefix: Prefix,
    validation_state: rustbgpd_wire::RpkiValidation,
    aspa_state: rustbgpd_wire::AspaValidation,
) -> rustbgpd_policy::RouteContext<'static> {
    rustbgpd_policy::RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state,
        aspa_state,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: Some(match prefix {
            Prefix::V4(_) => rustbgpd_policy::RouteFamily::Ipv4Unicast,
            Prefix::V6(_) => rustbgpd_policy::RouteFamily::Ipv6Unicast,
        }),
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

fn assert_route_server_prefix_set(
    compiled: &rustbgpd_policy::ir::CompiledChain,
    name: &str,
    expected: &[(&str, Option<u8>, Option<u8>, &str)],
) {
    let index = compiled
        .prefix_set_names
        .iter()
        .position(|candidate| candidate.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("compiled policy has no {name} prefix set"));
    let expected =
        rustbgpd_policy::sets::PrefixSet::new(expected.iter().map(|(prefix, ge, le, _)| {
            rustbgpd_policy::sets::PrefixSetEntry {
                prefix: route_server_test_prefix(prefix),
                ge: *ge,
                le: *le,
            }
        }));
    assert_eq!(
        compiled.prefix_sets[index].entries(),
        expected.entries(),
        "compiled {name} inventory must match the dated snapshot exactly"
    );
}

#[test]
fn v1_stable_v0_50_route_server_fixture_parses() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-stable/v0.50.0/route-server");
    let config_path = fixture.join("config.toml");
    let source = fs::read_to_string(&config_path).unwrap_or_else(|err| {
        panic!(
            "failed to read immutable v0.50.0 route-server fixture {}: {err}",
            config_path.display()
        );
    });
    let mut config: Config = toml::from_str(&source)
        .unwrap_or_else(|err| panic!("v0.50.0 route-server config no longer parses: {err}"));
    config
        .load_rpol_files(Some(&fixture))
        .unwrap_or_else(|err| panic!("v0.50.0 route-server rpol no longer loads: {err}"));
    config
        .validate()
        .unwrap_or_else(|err| panic!("v0.50.0 route-server config no longer validates: {err}"));
}

#[test]
fn v1_stable_v0_51_route_server_fixture_parses() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-stable/v0.51.0/route-server");
    let config_path = fixture.join("config.toml");
    let source = fs::read_to_string(&config_path).unwrap_or_else(|err| {
        panic!(
            "failed to read immutable v0.51.0 route-server fixture {}: {err}",
            config_path.display()
        );
    });
    let mut config: Config = toml::from_str(&source)
        .unwrap_or_else(|err| panic!("v0.51.0 route-server config no longer parses: {err}"));
    config
        .load_rpol_files(Some(&fixture))
        .unwrap_or_else(|err| panic!("v0.51.0 route-server rpol no longer loads: {err}"));
    config
        .validate()
        .unwrap_or_else(|err| panic!("v0.51.0 route-server config no longer validates: {err}"));
}

#[test]
fn v1_stable_v0_60_route_server_fixture_parses() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-stable/v0.60.0/route-server");
    let config_path = fixture.join("config.toml");
    let source = fs::read_to_string(&config_path).unwrap_or_else(|err| {
        panic!(
            "failed to read immutable v0.60.0 route-server fixture {}: {err}",
            config_path.display()
        );
    });
    let mut config: Config = toml::from_str(&source)
        .unwrap_or_else(|err| panic!("v0.60.0 route-server config no longer parses: {err}"));
    config
        .load_rpol_files(Some(&fixture))
        .unwrap_or_else(|err| panic!("v0.60.0 route-server rpol no longer loads: {err}"));
    config
        .validate()
        .unwrap_or_else(|err| panic!("v0.60.0 route-server config no longer validates: {err}"));
}

#[test]
fn v1_stable_v0_61_route_server_fixture_parses() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-stable/v0.61.0/route-server");
    let config_path = fixture.join("config.toml");
    let source = fs::read_to_string(&config_path).unwrap_or_else(|err| {
        panic!(
            "failed to read immutable v0.61.0 route-server fixture {}: {err}",
            config_path.display()
        );
    });
    let mut config: Config = toml::from_str(&source)
        .unwrap_or_else(|err| panic!("v0.61.0 route-server config no longer parses: {err}"));
    config
        .load_rpol_files(Some(&fixture))
        .unwrap_or_else(|err| panic!("v0.61.0 route-server rpol no longer loads: {err}"));
    config
        .validate()
        .unwrap_or_else(|err| panic!("v0.61.0 route-server config no longer validates: {err}"));
}

#[test]
fn v1_stable_v0_62_route_server_fixture_parses() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-stable/v0.62.0/route-server");
    let config_path = fixture.join("config.toml");
    let source = fs::read_to_string(&config_path).unwrap_or_else(|err| {
        panic!(
            "failed to read immutable v0.62.0 route-server fixture {}: {err}",
            config_path.display()
        );
    });
    let mut config: Config = toml::from_str(&source)
        .unwrap_or_else(|err| panic!("v0.62.0 route-server config no longer parses: {err}"));
    config
        .load_rpol_files(Some(&fixture))
        .unwrap_or_else(|err| panic!("v0.62.0 route-server rpol no longer loads: {err}"));
    config
        .validate()
        .unwrap_or_else(|err| panic!("v0.62.0 route-server config no longer validates: {err}"));
}

#[test]
fn v1_stable_v0_63_route_server_fixture_parses() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-stable/v0.63.0/route-server");
    let config_path = fixture.join("config.toml");
    let source = fs::read_to_string(&config_path).unwrap_or_else(|err| {
        panic!(
            "failed to read immutable v0.63.0 route-server fixture {}: {err}",
            config_path.display()
        );
    });
    let mut config: Config = toml::from_str(&source)
        .unwrap_or_else(|err| panic!("v0.63.0 route-server config no longer parses: {err}"));
    config
        .load_rpol_files(Some(&fixture))
        .unwrap_or_else(|err| panic!("v0.63.0 route-server rpol no longer loads: {err}"));
    config
        .validate()
        .unwrap_or_else(|err| panic!("v0.63.0 route-server config no longer validates: {err}"));
}

const V1_EFFECTIVE_DEFAULTS_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-v1-effective.sock"
principal = "local-admin"

[security.grpc.roles]
"local-admin" = "operator"

[peer_groups.context]
families = ["ipv6_unicast"]
hold_time = 300
graceful_restart = false
gr_restart_time = 0
gr_peer_restart_time_max = 1800
gr_stale_routes_time = 900
llgr_stale_time = 1800
disable_ipv4_unicast = true

[peer_groups.override]
families = ["ipv6_unicast"]
hold_time = 300
send_hold_time = 800
graceful_restart = false
gr_restart_time = 0
gr_peer_restart_time_max = 1800
gr_stale_routes_time = 900
llgr_stale_time = 1800
disable_ipv4_unicast = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors]]
address = "2001:db8::2"
remote_asn = 65003
peer_group = "context"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
peer_group = "override"
families = ["ipv4_unicast"]
hold_time = 45
send_hold_time = 1000
graceful_restart = true
gr_restart_time = 240
gr_peer_restart_time_max = 300
gr_stale_routes_time = 720
llgr_stale_time = 60
disable_ipv4_unicast = false

[[neighbors]]
address = "2001:db8::5"
remote_asn = 65005
"#;

const V1_CLUSTER_ID_DEFAULTS_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-v1-cluster-id.sock"
principal = "local-admin"

[security.grpc.roles]
"local-admin" = "operator"

[peer_groups.rr]
route_reflector_client = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
peer_group = "rr"
"#;

#[expect(
    clippy::too_many_lines,
    reason = "the v1 inventory checker requires all contextual-default proofs in one named test"
)]
#[test]
fn v1_stable_effective_defaults_match_runtime_resolution() {
    macro_rules! assert_v1_effective_default {
        ($path:literal, $actual:expr, $expected:expr) => {
            assert_eq!(
                $actual, $expected,
                "runtime effective default drifted for {}",
                $path
            );
        };
    }
    macro_rules! assert_v1_family_case {
        ($case:literal, $actual:expr, $expected:expr) => {
            assert_eq!(
                $actual.as_slice(),
                $expected,
                "runtime effective family default drifted for {}",
                $case
            );
        };
    }

    let config =
        parse_strict(V1_EFFECTIVE_DEFAULTS_TOML).expect("contextual-default fixture must load");
    let explicit_dynamic_limit_toml = V1_EFFECTIVE_DEFAULTS_TOML.replacen(
        "listen_port = 179",
        "listen_port = 179\ndynamic_neighbor_limit = 500",
        1,
    );
    let explicit_dynamic_limit = parse_strict(&explicit_dynamic_limit_toml)
        .expect("explicit dynamic-neighbor limit fixture must load");
    let bare = config
        .resolve_neighbor(&config.neighbors[0])
        .expect("bare neighbor must resolve");
    let inherited = config
        .resolve_neighbor(&config.neighbors[1])
        .expect("peer-group neighbor must resolve");
    let overridden = config
        .resolve_neighbor(&config.neighbors[2])
        .expect("direct-override neighbor must resolve");
    let bare_ipv6 = config
        .resolve_neighbor(&config.neighbors[3])
        .expect("bare IPv6 neighbor must resolve");
    let bare_peer = &bare.transport_config.peer;
    let bare_transport = &bare.transport_config;
    let cluster_id = config.cluster_id();
    let explicit_dynamic_neighbor_limit = explicit_dynamic_limit.effective_dynamic_neighbor_limit();
    let dynamic_neighbor_limit = (
        config.effective_dynamic_neighbor_limit(),
        explicit_dynamic_neighbor_limit,
    );
    let disable_ipv4_unicast = bare_peer.disable_ipv4_unicast;
    let gr_peer_restart_time_max = bare_transport.gr_peer_restart_time_max;
    let gr_restart_time = bare_peer.gr_restart_time;
    let gr_stale_routes_time = bare_transport.gr_stale_routes_time;
    let graceful_restart = bare_peer.graceful_restart;
    let hold_time = bare_peer.hold_time;
    let min_hold_time = bare_peer.min_hold_time;
    let llgr_stale_time = (bare_peer.llgr_stale_time, bare_transport.llgr_stale_time);
    let send_hold_time = bare_peer.send_hold_time;

    // Mutation-red: each full path is bound to its actual production-resolved
    // value and an explicit expected value; deleting or weakening any row is red.
    assert_v1_effective_default!("Global.cluster_id", cluster_id, None);
    assert_v1_effective_default!(
        "Global.dynamic_neighbor_limit",
        dynamic_neighbor_limit,
        (100, 500)
    );
    assert_v1_effective_default!("Neighbor.disable_ipv4_unicast", disable_ipv4_unicast, false);
    assert_v1_effective_default!(
        "Neighbor.gr_peer_restart_time_max",
        gr_peer_restart_time_max,
        4095
    );
    assert_v1_effective_default!("Neighbor.gr_restart_time", gr_restart_time, 120);
    assert_v1_effective_default!("Neighbor.gr_stale_routes_time", gr_stale_routes_time, 360);
    assert_v1_effective_default!("Neighbor.graceful_restart", graceful_restart, true);
    assert_v1_effective_default!("Neighbor.hold_time", hold_time, 90);
    assert_v1_effective_default!("Neighbor.llgr_stale_time", llgr_stale_time, (0, 0));
    assert_v1_effective_default!("Neighbor.min_hold_time", min_hold_time, None);
    assert_v1_effective_default!("Neighbor.send_hold_time", send_hold_time, 480);

    // Mutation-red: changing the address-derived default, removing peer-group
    // inheritance, or making the group outrank a neighbor override changes one
    // of these typed rows.
    assert_v1_family_case!(
        "bare_ipv4",
        bare.transport_config.peer.families,
        &[(Afi::Ipv4, Safi::Unicast)]
    );
    assert_v1_family_case!(
        "bare_ipv6",
        bare_ipv6.transport_config.peer.families,
        &[(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    );
    assert_v1_family_case!(
        "group_overrides_address_default",
        inherited.transport_config.peer.families,
        &[(Afi::Ipv6, Safi::Unicast)]
    );
    assert_v1_family_case!(
        "neighbor_overrides_group",
        overridden.transport_config.peer.families,
        &[(Afi::Ipv4, Safi::Unicast)]
    );

    let effective = |resolved: &ResolvedNeighbor| {
        let transport = &resolved.transport_config;
        (
            transport.peer.hold_time,
            transport.peer.send_hold_time,
            transport.peer.graceful_restart,
            transport.peer.gr_restart_time,
            transport.gr_peer_restart_time_max,
            transport.gr_stale_routes_time,
            (transport.peer.llgr_stale_time, transport.llgr_stale_time),
            transport.peer.disable_ipv4_unicast,
        )
    };

    // Mutation-red: removing peer-group fallback for any inventoried Neighbor
    // field, or replacing derived send-hold max(480, 2 * 300) with 480, fails.
    assert_eq!(
        effective(&inherited),
        (300, 600, false, 0, 1800, 900, (1800, 1800), true)
    );
    // Mutation-red: making peer-group values outrank any direct Neighbor
    // override changes this tuple (and disable_ipv4_unicast may fail validation).
    assert_eq!(
        effective(&overridden),
        (45, 1000, true, 240, 300, 720, (60, 60), false)
    );

    let rr =
        parse_strict(V1_CLUSTER_ID_DEFAULTS_TOML).expect("inherited RR-client fixture must load");
    let explicit_rr_toml = V1_CLUSTER_ID_DEFAULTS_TOML.replace(
        "listen_port = 179",
        "listen_port = 179\ncluster_id = \"10.0.0.9\"",
    );
    let explicit_rr =
        parse_strict(&explicit_rr_toml).expect("explicit cluster-id fixture must load");

    // Mutation-red: unconditional router-id fallback, ignoring inherited RR
    // status, or ignoring an explicit cluster_id changes this three-case tuple.
    assert_eq!(
        (
            config.cluster_id(),
            rr.cluster_id(),
            explicit_rr.cluster_id()
        ),
        (
            None,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            Some(Ipv4Addr::new(10, 0, 0, 9))
        )
    );
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

/// The implicit owner-only UDS listener synthesized whenever
/// `[global.telemetry.grpc_uds]` is not declared.
fn implicit_uds_listener(config: &Config) -> GrpcListener {
    GrpcListener::Uds {
        path: config.default_grpc_uds_path(),
        mode: 0o600,
        access_mode: GrpcAccessMode::ReadWrite,
        max_tier: GrpcMaxTier::OperatorOnly,
        token_file: None,
        principal: None,
    }
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

fn tcp_ao_test_keyring(key_count: usize) -> TcpAoKeyringConfig {
    TcpAoKeyringConfig(
        (0..key_count)
            .map(|key_id| TcpAoConfig {
                key: "secret".to_string(),
                send_id: u8::try_from(key_id).expect("test keyring is bounded to 256 keys"),
                recv_id: u8::try_from(key_id).expect("test keyring is bounded to 256 keys"),
                algorithm: "hmac(sha256)".to_string(),
                preferred: false,
                deprecated: false,
            })
            .collect(),
    )
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

/// RFC 9107 `orr_vantage` config-surface harness: one iBGP RR (asn
/// 65001) with the given neighbor + peer-group field bodies.
fn orr_toml(neighbor_fields: &str, group_fields: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.clients]
{group_fields}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
peer_group = "clients"
{neighbor_fields}
"#
    )
}

fn orr_dynamic_toml(neighbor_fields: &str, dynamic_group_fields: &str) -> String {
    format!(
        r#"
{base}

[peer_groups.dynamic]
{dynamic_group_fields}

[[dynamic_neighbors]]
prefix = "10.0.1.0/24"
peer_group = "dynamic"
remote_asn = 65001
"#,
        base = orr_toml(neighbor_fields, "")
    )
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

// -----------------------------------------------------------------------
// gNMI dial-out config validation (LAN-471)
// -----------------------------------------------------------------------

const DIALOUT_SESSION_STATE_PATH: &str = "network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=*]/state/session-state";

fn gnmi_dialout_toml(target_fields: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[gnmi_dialout]
[[gnmi_dialout.targets]]
name = "collector-a"
address = "192.0.2.10:57400"
paths = ["{DIALOUT_SESSION_STATE_PATH}"]
{target_fields}
"#
    )
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

fn test_neighbor(addr: &str, asn: u32) -> Neighbor {
    Neighbor {
        min_hold_time: None,
        address: addr.to_string(),
        interface: None,
        remote_asn: asn,
        description: None,
        peer_group: None,
        hold_time: None,
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefixes_out_ipv4: None,
        max_prefixes_out_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: Some(false),
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: Some(false),
        orr_vantage: None,
        route_server_client: Some(false),
        per_client_best: None,
        next_hop_ownership: None,
        interpret_rfc1997: None,
        rs_control_communities: None,
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

fn loaded_config_with_neighbor_address(address: &str) -> Config {
    let toml_str = tier_authorized_uds_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "{address}"
remote_asn = 65002
"#
    ));
    Config::load_toml_with_diagnostics(&toml_str, "canonicalization test").unwrap()
}

fn rfc8212_representation_toml(epoch: Option<&str>, policy: Option<bool>) -> String {
    let source = policy.map_or_else(
        || valid_toml().to_string(),
        |enabled| {
            valid_toml().replace(
                "listen_port = 179",
                &format!("listen_port = 179\nebgp_requires_policy = {enabled}"),
            )
        },
    );
    epoch.map_or(source.clone(), |epoch| {
        format!("config_epoch = {epoch}\n{source}")
    })
}

/// `valid_toml()` with `ebgp_requires_policy = true` inside `[global]`.
fn ebgp_requires_policy_toml() -> String {
    rfc8212_representation_toml(None, Some(true))
}

// ── Dynamic neighbor config tests ───────────────────────────────

fn dynamic_modes_toml(group_fields: &str, remote_asn: u32) -> String {
    format!(
        r#"
{base}

[peer_groups.modes]
{group_fields}

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "modes"
remote_asn = {remote_asn}
"#,
        base = valid_toml()
    )
}

fn resolve_dynamic_modes(config: &Config, remote_asn: u32) -> ResolvedNeighbor {
    config
        .resolve_dynamic_neighbor(
            "10.0.0.42".parse().unwrap(),
            remote_asn,
            "dynamic",
            &config.peer_groups["modes"],
            "modes",
            false,
        )
        .unwrap()
}

fn dynamic_tcp_ao_toml(ranges_and_neighbors: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90

{ranges_and_neighbors}
"#
    )
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

fn dynamic_tcp_ao_transaction_config(protected: Option<(&str, &str)>, extra: &str) -> Config {
    let protected = protected.map_or_else(String::new, |(prefix, key)| {
        format!(
            "[[dynamic_neighbors]]\nprefix = \"{prefix}\"\npeer_group = \"dynamic\"\ntcp_ao = {{ key = \"{key}\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }}\n"
        )
    });
    parse(&format!(
        "{}\n[peer_groups.dynamic]\nhold_time = 90\n{protected}{extra}",
        valid_toml()
    ))
    .unwrap()
}

fn persistence_order_fixture(reverse: bool, bulk_statement_count: usize) -> Config {
    let source = format!(
        "{}\n[policy.definitions.seed]\n[[policy.definitions.seed.statements]]\n\
         action = \"permit\"\nprefix = \"2001:db8:1234:5678::/64\"\nge = 64\n",
        valid_toml()
    );
    let mut config = parse_schema_only(&source).unwrap();
    let statement = config
        .policy
        .definitions
        .remove("seed")
        .unwrap()
        .statements
        .remove(0);
    let mut names = ["alpha", "beta", "gamma", "zeta"];
    if reverse {
        names.reverse();
    }
    for name in names {
        let hold_time = match name {
            "alpha" => 30,
            "beta" => 45,
            "gamma" => 60,
            "zeta" => 90,
            _ => unreachable!(),
        };
        config.peer_groups.insert(
            name.to_string(),
            PeerGroupConfig {
                hold_time: Some(hold_time),
                ..PeerGroupConfig::default()
            },
        );
        let role = match name {
            "alpha" => GrpcRoleConfig::Observer,
            "beta" | "gamma" => GrpcRoleConfig::Automation,
            "zeta" => GrpcRoleConfig::Operator,
            _ => unreachable!(),
        };
        config.security.grpc.roles.insert(name.to_string(), role);
        let mut statements = if name == "zeta" {
            vec![statement.clone(); bulk_statement_count]
        } else {
            Vec::new()
        };
        if statements.len() == 2 {
            statements[1].action = "deny".to_string();
            statements[1].prefix = Some("198.51.100.0/24".to_string());
            statements[1].ge = Some(24);
        }
        config.policy.definitions.insert(
            name.to_string(),
            NamedPolicyConfig {
                default_action: "permit".to_string(),
                statements,
            },
        );
        config.policy.neighbor_sets.insert(
            name.to_string(),
            NeighborSetConfig {
                addresses: vec![format!("192.0.2.{hold_time}")],
                ..NeighborSetConfig::default()
            },
        );
        config.policy.datasets.insert(
            name.to_string(),
            DatasetFileConfig {
                path: format!("/var/lib/rustbgpd/{name}.set"),
            },
        );
    }
    config
}

fn reverse_insertion_persistence_pair() -> (Config, Config) {
    for _ in 0..128 {
        let left = persistence_order_fixture(false, 2);
        let right = persistence_order_fixture(true, 2);
        let all_raw_orders_differ = left.peer_groups.keys().collect::<Vec<_>>()
            != right.peer_groups.keys().collect::<Vec<_>>()
            && left.security.grpc.roles.keys().collect::<Vec<_>>()
                != right.security.grpc.roles.keys().collect::<Vec<_>>()
            && left.policy.definitions.keys().collect::<Vec<_>>()
                != right.policy.definitions.keys().collect::<Vec<_>>()
            && left.policy.neighbor_sets.keys().collect::<Vec<_>>()
                != right.policy.neighbor_sets.keys().collect::<Vec<_>>()
            && left.policy.datasets.keys().collect::<Vec<_>>()
                != right.policy.datasets.keys().collect::<Vec<_>>();
        if all_raw_orders_differ {
            return (left, right);
        }
    }
    panic!("failed to construct distinct raw HashMap iteration orders");
}

fn rfc8212_transaction_fixture(
    epoch: Option<&str>,
    policy: Option<bool>,
    add_neighbor: bool,
) -> Config {
    let mut source = rfc8212_representation_toml(epoch, policy);
    if add_neighbor {
        source.push_str(
            r#"
[[neighbors]]
address = "192.0.2.44"
remote_asn = 65044
"#,
        );
    }
    parse(&source).unwrap()
}

#[cfg(target_os = "linux")]
fn linux_vm_hwm_bytes() -> usize {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse::<usize>()
                .ok()
        })
        .unwrap()
        * 1024
}

#[cfg(target_os = "linux")]
fn persistence_probe_fixture() -> Config {
    let mut config = persistence_order_fixture(false, 1);
    let statement = config.policy.definitions["zeta"].statements[0].clone();
    config.policy.definitions.clear();
    for member in 0..320 {
        config.policy.definitions.insert(
            format!("member-{member:03}"),
            NamedPolicyConfig {
                default_action: "permit".to_string(),
                statements: vec![statement.clone(); 10_000],
            },
        );
    }
    config
}

#[cfg(target_os = "linux")]
fn run_persistence_probe_child(arm: &str, receipt: &Path) {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    use std::time::Instant;

    let config = persistence_probe_fixture();
    let baseline = linux_vm_hwm_bytes();
    let started = Instant::now();
    assert!(matches!(arm, "direct" | "sorted" | "borrowed" | "owned"));
    let owned = (arm == "owned").then(|| config.clone());
    let rendered = persisted_config_document(owned.as_ref().unwrap_or(&config)).unwrap();
    std::hint::black_box(&owned);
    let elapsed = started.elapsed().as_nanos();
    let direct_maps =
        super::schema::PERSISTENCE_PROBE_DIRECT_MAPS.swap(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(direct_maps > 0, arm == "direct");
    let peak = linux_vm_hwm_bytes();
    let growth = peak.saturating_sub(baseline);
    let bytes = rendered.len();
    let sha256 = Sha256::digest(rendered.as_bytes()).iter().fold(
        String::with_capacity(64),
        |mut hex, byte| {
            write!(&mut hex, "{byte:02x}").unwrap();
            hex
        },
    );
    let mut round_tripped: Config = toml::from_str(&rendered).unwrap();
    drop(rendered);
    round_tripped.config_epoch = None;
    round_tripped.global.ebgp_requires_policy = None;
    assert_eq!(round_tripped, config);
    fs::write(
        receipt,
        format!(
            "{bytes},{elapsed},{baseline},{peak},{growth},{},{}",
            usize::from(owned.is_some()),
            sha256
        ),
    )
    .unwrap();
    eprintln!(
        "arm={arm} bytes={bytes} sha256={sha256} elapsed_ns={elapsed} baseline={baseline} peak={peak} growth={growth}"
    );
}

#[cfg(target_os = "linux")]
fn assert_persistence_probe_receipts(direct: &[u128], sorted: &[u128]) {
    const MIB: usize = 1024 * 1024;

    assert_eq!(direct[0], sorted[0]);
    assert!(direct[4] >= direct[0] / 2);
    assert!(sorted[4] >= sorted[0] / 2);
    let allowance = ((direct[4] * 5) / 100).max((64 * MIB) as u128);
    assert!(sorted[4] <= direct[4] + allowance);
    assert!(sorted[1] <= direct[1] * 115 / 100 + 250_000_000);
}

#[cfg(target_os = "linux")]
fn assert_borrowed_persistence_probe_receipts(
    borrowed: &[u128],
    borrowed_sha256: &str,
    owned: &[u128],
    owned_sha256: &str,
) {
    const MIB: u128 = 1024 * 1024;

    assert_eq!(borrowed[0], owned[0]);
    assert_eq!(borrowed_sha256, owned_sha256);
    assert_eq!(borrowed[5], 0);
    assert_eq!(owned[5], 1);
    let clone_cost_floor = (borrowed[4] / 10).max(128 * MIB);
    assert!(
        owned[4] >= borrowed[4] + clone_cost_floor,
        "borrowed projection lost its material HWM advantage: borrowed={borrowed:?} owned={owned:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "release-only fresh-process 3.2M-statement persistence A/B"]
#[allow(
    clippy::assertions_on_constants,
    reason = "the ignored scale probe must reject accidental debug-profile runs"
)]
fn persisted_config_release_scale_probe() {
    use std::process::Command;

    const ARM: &str = "RUSTBGPD_PERSISTENCE_PROBE_ARM";
    const RECEIPT: &str = "RUSTBGPD_PERSISTENCE_PROBE_RECEIPT";
    assert!(!cfg!(debug_assertions), "run with --release");
    if let (Ok(arm), Ok(receipt)) = (std::env::var(ARM), std::env::var(RECEIPT)) {
        run_persistence_probe_child(&arm, Path::new(&receipt));
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let direct_file = NamedTempFile::new().unwrap();
    let sorted_file = NamedTempFile::new().unwrap();
    let borrowed_file = NamedTempFile::new().unwrap();
    let owned_file = NamedTempFile::new().unwrap();
    for (arm, receipt) in [
        ("direct", &direct_file),
        ("sorted", &sorted_file),
        ("borrowed", &borrowed_file),
        ("owned", &owned_file),
    ] {
        assert!(
            Command::new(&executable)
                .args([
                    "config::tests::persisted_config_release_scale_probe",
                    "--ignored",
                    "--exact",
                    "--nocapture"
                ])
                .env(ARM, arm)
                .env(RECEIPT, receipt.path())
                .status()
                .unwrap()
                .success()
        );
    }
    let read = |path: &Path| -> (Vec<u128>, String) {
        let receipt = fs::read_to_string(path).unwrap();
        let (numbers, sha256) = receipt.rsplit_once(',').unwrap();
        (
            numbers
                .split(',')
                .map(|value| value.parse().unwrap())
                .collect(),
            sha256.to_string(),
        )
    };
    let (direct, _) = read(direct_file.path());
    let (sorted, _) = read(sorted_file.path());
    let (borrowed, borrowed_sha256) = read(borrowed_file.path());
    let (owned, owned_sha256) = read(owned_file.path());
    assert_persistence_probe_receipts(&direct, &sorted);
    assert_borrowed_persistence_probe_receipts(&borrowed, &borrowed_sha256, &owned, &owned_sha256);
}

#[derive(Debug)]
struct BoundedWriterRow {
    attempt: usize,
    arm: String,
    bytes: usize,
    sha256: String,
    elapsed_ns: u128,
    baseline_hwm: usize,
    peak_hwm: usize,
    growth: usize,
    statements: usize,
    max_chunk: usize,
}

fn verify_bounded_writer_receipt(source: &str) {
    const MIB: usize = 1024 * 1024;
    const HEADER: &str = "attempt\tpair\tslot\tarm\tdocument_bytes\tsha256\telapsed_ns\tbaseline_hwm_bytes\tpeak_hwm_bytes\tgrowth_bytes\tstatements\tmax_chunk_statements";
    let mut lines = source.lines();
    assert_eq!(lines.next(), Some(HEADER));
    let rows: Vec<_> = lines
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 12);
            let number = |index: usize| fields[index].parse::<usize>().unwrap();
            BoundedWriterRow {
                attempt: number(0),
                arm: fields[3].to_string(),
                bytes: number(4),
                sha256: fields[5].to_string(),
                elapsed_ns: fields[6].parse().unwrap(),
                baseline_hwm: number(7),
                peak_hwm: number(8),
                growth: number(9),
                statements: number(10),
                max_chunk: number(11),
            }
        })
        .collect();
    assert_eq!(rows.len(), 6);
    let order = [
        "legacy", "bounded", "bounded", "legacy", "legacy", "bounded",
    ];
    let first = &rows[0];
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row.attempt, index + 1);
        assert_eq!(row.arm, order[index]);
        assert_eq!((row.bytes, &row.sha256), (first.bytes, &first.sha256));
        assert_eq!(row.sha256.len(), 64);
        assert!(row.elapsed_ns > 0 && row.baseline_hwm > 0 && row.peak_hwm > 0);
        assert_eq!(row.peak_hwm.saturating_sub(row.baseline_hwm), row.growth);
        if row.arm == "bounded" {
            assert_eq!((row.statements, row.max_chunk), (3_200_000, 256));
        } else {
            assert_eq!((row.statements, row.max_chunk), (0, 0));
        }
    }
    let pairs = [(0, 1), (3, 2), (4, 5)];
    let mut legacy_times = Vec::new();
    let mut bounded_times = Vec::new();
    for (legacy_index, bounded_index) in pairs {
        let legacy = &rows[legacy_index];
        let bounded = &rows[bounded_index];
        let cap = (legacy.growth * 60 / 100).min(first.bytes * 3 + 64 * MIB);
        assert!(
            bounded.growth <= cap,
            "bounded={bounded:?} legacy={legacy:?}"
        );
        assert!(bounded.elapsed_ns <= legacy.elapsed_ns * 3 / 2);
        legacy_times.push(legacy.elapsed_ns);
        bounded_times.push(bounded.elapsed_ns);
    }
    legacy_times.sort_unstable();
    bounded_times.sort_unstable();
    assert!(bounded_times[1] <= legacy_times[1] * 5 / 4);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "release-only six-child 3.2M-statement bounded-writer A/B"]
fn bounded_writer_release_probe() {
    use sha2::{Digest as _, Sha256};
    use std::{fmt::Write as _, process::Command, time::Instant};

    const ARM: &str = "RUSTBGPD_BOUNDED_WRITER_ARM";
    const ATTEMPT: &str = "RUSTBGPD_BOUNDED_WRITER_ATTEMPT";
    const RECEIPT: &str = "RUSTBGPD_BOUNDED_WRITER_RECEIPT";
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "run with --release"
    );
    if let (Ok(arm), Ok(attempt), Ok(receipt)) = (
        std::env::var(ARM),
        std::env::var(ATTEMPT),
        std::env::var(RECEIPT),
    ) {
        let mut config = persistence_probe_fixture();
        let baseline = linux_vm_hwm_bytes();
        let started = Instant::now();
        let (document, stats) = match arm.as_str() {
            "legacy" => (
                persisted_config_document(&config).unwrap(),
                super::canonical::BoundedRenderStats::default(),
            ),
            "bounded" => super::canonical::render_document_bounded(&mut config).unwrap(),
            other => panic!("unknown bounded-writer arm {other}"),
        };
        let elapsed = started.elapsed().as_nanos();
        let peak = linux_vm_hwm_bytes();
        let sha = Sha256::digest(document.as_bytes()).iter().fold(
            String::with_capacity(64),
            |mut out, byte| {
                write!(&mut out, "{byte:02x}").unwrap();
                out
            },
        );
        fs::write(
            receipt,
            format!(
                "{}\t{}\t{}\t{arm}\t{}\t{sha}\t{elapsed}\t{baseline}\t{peak}\t{}\t{}\t{}\n",
                attempt,
                attempt.parse::<usize>().unwrap().div_ceil(2),
                (attempt.parse::<usize>().unwrap() - 1) % 2 + 1,
                document.len(),
                peak.saturating_sub(baseline),
                stats.statements,
                stats.max_chunk_statements,
            ),
        )
        .unwrap();
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut output = String::from(
        "attempt\tpair\tslot\tarm\tdocument_bytes\tsha256\telapsed_ns\tbaseline_hwm_bytes\tpeak_hwm_bytes\tgrowth_bytes\tstatements\tmax_chunk_statements\n",
    );
    for (index, arm) in [
        "legacy", "bounded", "bounded", "legacy", "legacy", "bounded",
    ]
    .iter()
    .enumerate()
    {
        let receipt = NamedTempFile::new().unwrap();
        assert!(
            Command::new(&executable)
                .args([
                    "config::tests::bounded_writer_release_probe",
                    "--ignored",
                    "--exact",
                    "--nocapture"
                ])
                .env(ARM, arm)
                .env(ATTEMPT, (index + 1).to_string())
                .env(RECEIPT, receipt.path())
                .status()
                .unwrap()
                .success()
        );
        output.push_str(&fs::read_to_string(receipt.path()).unwrap());
    }
    verify_bounded_writer_receipt(&output);
    let output_path = std::env::var("RUSTBGPD_BOUNDED_WRITER_OUTPUT")
        .expect("RUSTBGPD_BOUNDED_WRITER_OUTPUT is required");
    retain_persistence_phase_receipt(Path::new(&output_path), &output);
}

#[derive(Clone, Debug)]
struct PersistencePhaseRow {
    attempt: usize,
    pair: usize,
    slot: usize,
    arm: String,
    phase: String,
    policy_definitions: usize,
    statements: usize,
    total: usize,
    bytes: usize,
    sha256: String,
    elapsed_ns: u128,
    allocated: usize,
    resident: usize,
    rss: usize,
    hwm: usize,
}

#[cfg(all(target_os = "linux", feature = "jemalloc"))]
fn persistence_phase_memory() -> (usize, usize, usize, usize) {
    use tikv_jemalloc_ctl::{epoch, stats};
    epoch::advance().unwrap();
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let read = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap()
            * 1024
    };
    (
        stats::allocated::read().unwrap(),
        stats::resident::read().unwrap(),
        read("VmRSS:"),
        read("VmHWM:"),
    )
}

#[cfg(all(target_os = "linux", feature = "jemalloc"))]
fn run_persistence_phase_child(arm: &str, attempt: usize, receipt: &Path) {
    use sha2::{Digest as _, Sha256};
    use std::{fmt::Write as _, time::Instant};

    let config = persistence_probe_fixture();
    let started = Instant::now();
    let mut snapshots = Vec::new();
    let mut observe = |phase: &'static str| {
        snapshots.push((
            phase,
            started.elapsed().as_nanos(),
            persistence_phase_memory(),
        ));
    };
    observe("fixture-built");
    let document = match arm {
        "production" => {
            let document = persisted_config_document(&config).unwrap();
            observe("production-complete");
            document
        }
        "phased" => {
            let rendered =
                super::canonical::render_with_phase_observer(&config, &mut observe).unwrap();
            let document = format!("{PERSISTED_CONFIG_HEADER}\n{rendered}");
            std::hint::black_box((&rendered, &document));
            observe("header-appended");
            assert_eq!(document, persisted_config_document(&config).unwrap());
            document
        }
        other => panic!("unknown persistence phase arm {other}"),
    };
    let sha256 = Sha256::digest(document.as_bytes()).iter().fold(
        String::with_capacity(64),
        |mut out, byte| {
            write!(&mut out, "{byte:02x}").unwrap();
            out
        },
    );
    let mut out = String::new();
    for (phase, elapsed_ns, (allocated, resident, rss, hwm)) in snapshots {
        writeln!(
            out,
            "{attempt}\t{}\t{}\t{arm}\t{phase}\t320\t10000\t3200000\t{}\t{sha256}\t{elapsed_ns}\t{allocated}\t{resident}\t{rss}\t{hwm}",
            attempt.div_ceil(2),
            ((attempt - 1) % 2) + 1,
            document.len(),
        )
        .unwrap();
    }
    fs::write(receipt, out).unwrap();
}

fn parse_persistence_phase_receipt(source: &str) -> Vec<PersistencePhaseRow> {
    const HEADER: &str = "attempt\tpair\tslot_in_pair\tarm\tphase\tpolicy_definitions\tstatements_per_definition\ttotal_statements\tdocument_bytes\tsha256\telapsed_ns\tjemalloc_allocated_bytes\tjemalloc_resident_bytes\tvmrss_bytes\tvmhwm_bytes";
    let mut lines = source.lines();
    assert_eq!(lines.next(), Some(HEADER));
    lines
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 15, "malformed receipt row: {line}");
            let number = |index: usize| fields[index].parse::<usize>().unwrap();
            let row = PersistencePhaseRow {
                attempt: number(0),
                pair: number(1),
                slot: number(2),
                arm: fields[3].to_string(),
                phase: fields[4].to_string(),
                policy_definitions: number(5),
                statements: number(6),
                total: number(7),
                bytes: number(8),
                sha256: fields[9].to_string(),
                elapsed_ns: fields[10].parse().unwrap(),
                allocated: number(11),
                resident: number(12),
                rss: number(13),
                hwm: number(14),
            };
            assert!(row.elapsed_ns > 0 && row.allocated > 0 && row.resident > 0);
            assert!(row.rss > 0 && row.hwm > 0);
            assert!(row.bytes > 0);
            assert!(
                row.sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            );
            row
        })
        .collect()
}

#[derive(Debug, Eq, PartialEq)]
enum PersistencePhaseDecision {
    Go,
    NoGo,
    Inconclusive,
}

#[expect(
    clippy::too_many_lines,
    reason = "single verifier owns the phase roster and decision boundary"
)]
fn verify_persistence_phase_receipt(source: &str) -> PersistencePhaseDecision {
    const MIB: usize = 1024 * 1024;
    const HWM_ACCOUNTING_JITTER: usize = 4 * MIB;
    let rows = parse_persistence_phase_receipt(source);
    assert_eq!(rows.len(), 21);
    assert!(rows.iter().all(|row| (1..=6).contains(&row.attempt)));
    let order = [
        "production",
        "phased",
        "phased",
        "production",
        "production",
        "phased",
    ];
    let first = rows.first().unwrap();
    for attempt in 1..=6 {
        let attempt_rows: Vec<_> = rows.iter().filter(|row| row.attempt == attempt).collect();
        let phases: Vec<_> = attempt_rows.iter().map(|row| row.phase.as_str()).collect();
        let expected = if order[attempt - 1] == "production" {
            vec!["fixture-built", "production-complete"]
        } else {
            vec![
                "fixture-built",
                "graph-built",
                "rendered-with-graph",
                "graph-dropped",
                "header-appended",
            ]
        };
        assert_eq!(phases, expected, "attempt {attempt} phase roster");
        for pair in attempt_rows.windows(2) {
            assert!(pair[0].elapsed_ns < pair[1].elapsed_ns);
            assert!(pair[0].hwm.saturating_sub(pair[1].hwm) <= HWM_ACCOUNTING_JITTER);
        }
        for row in attempt_rows {
            assert_eq!(
                (row.pair, row.slot, row.arm.as_str()),
                (
                    attempt.div_ceil(2),
                    ((attempt - 1) % 2) + 1,
                    order[attempt - 1]
                )
            );
            assert_eq!(
                (row.policy_definitions, row.statements, row.total),
                (320, 10_000, 3_200_000)
            );
            assert_eq!(
                (row.bytes, row.sha256.as_str()),
                (first.bytes, first.sha256.as_str())
            );
            assert_eq!(row.sha256.len(), 64);
        }
    }
    assert_eq!(rows.iter().map(|row| row.attempt).max(), Some(6));
    let mut material_pairs = 0;
    let mut noisy_pairs = 0;
    for pair in 1..=3 {
        let production_fixture = rows
            .iter()
            .find(|row| row.pair == pair && row.arm == "production" && row.phase == "fixture-built")
            .unwrap();
        let production_complete = rows
            .iter()
            .find(|row| row.pair == pair && row.phase == "production-complete")
            .unwrap();
        let phased = |phase| {
            rows.iter()
                .find(|row| row.pair == pair && row.arm == "phased" && row.phase == phase)
                .unwrap()
        };
        let graph = phased("graph-dropped");
        let header = phased("header-appended");
        let phased_fixture = phased("fixture-built");
        let live_floor = (first.bytes / 4).max(128 * MIB);
        assert!(
            header.allocated.saturating_sub(graph.allocated) >= live_floor,
            "pair {pair} did not retain both rendered documents"
        );
        let resident_floor = (first.bytes / 10).max(64 * MIB);
        let prior_hwm = rows
            .iter()
            .filter(|row| row.pair == pair && row.arm == "phased" && row.phase != "header-appended")
            .map(|row| row.hwm)
            .max()
            .unwrap();
        let peak_delta = header.hwm.saturating_sub(prior_hwm);
        let live_delta = header
            .resident
            .saturating_sub(graph.resident)
            .max(header.rss.saturating_sub(graph.rss));
        material_pairs += usize::from(peak_delta >= resident_floor || live_delta >= resident_floor);
        assert!(production_complete.hwm.abs_diff(header.hwm) <= 64 * MIB);
        let fixture_noise_floor = (first.bytes / 20).max(16 * MIB);
        noisy_pairs += usize::from(
            production_fixture
                .allocated
                .abs_diff(phased_fixture.allocated)
                > fixture_noise_floor,
        );
    }
    if noisy_pairs > 0 {
        PersistencePhaseDecision::Inconclusive
    } else if material_pairs >= 2 {
        PersistencePhaseDecision::Go
    } else {
        PersistencePhaseDecision::NoGo
    }
}

fn retain_persistence_phase_receipt(path: &Path, source: &str) {
    assert!(
        !path.exists(),
        "refusing existing receipt {}",
        path.display()
    );
    fs::write(path, source).unwrap();
    assert_eq!(fs::read_to_string(path).unwrap(), source);
}

#[cfg(all(target_os = "linux", feature = "jemalloc"))]
#[test]
#[ignore = "release-only six-child 3.2M-statement phase attribution"]
fn persisted_config_phase_attribution_release_probe() {
    use std::process::Command;
    const ARM: &str = "RUSTBGPD_PERSISTENCE_PHASE_ARM";
    const ATTEMPT: &str = "RUSTBGPD_PERSISTENCE_PHASE_ATTEMPT";
    const RECEIPT: &str = "RUSTBGPD_PERSISTENCE_PHASE_RECEIPT";
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "run with --release"
    );
    if let (Ok(arm), Ok(attempt), Ok(receipt)) = (
        std::env::var(ARM),
        std::env::var(ATTEMPT),
        std::env::var(RECEIPT),
    ) {
        run_persistence_phase_child(&arm, attempt.parse().unwrap(), Path::new(&receipt));
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut output = format!(
        "{}\n",
        "attempt\tpair\tslot_in_pair\tarm\tphase\tpolicy_definitions\tstatements_per_definition\ttotal_statements\tdocument_bytes\tsha256\telapsed_ns\tjemalloc_allocated_bytes\tjemalloc_resident_bytes\tvmrss_bytes\tvmhwm_bytes"
    );
    for (index, arm) in [
        "production",
        "phased",
        "phased",
        "production",
        "production",
        "phased",
    ]
    .iter()
    .enumerate()
    {
        let receipt = NamedTempFile::new().unwrap();
        assert!(
            Command::new(&executable)
                .args([
                    "config::tests::persisted_config_phase_attribution_release_probe",
                    "--ignored",
                    "--exact",
                    "--nocapture"
                ])
                .env(ARM, arm)
                .env(ATTEMPT, (index + 1).to_string())
                .env(RECEIPT, receipt.path())
                .status()
                .unwrap()
                .success()
        );
        output.push_str(&fs::read_to_string(receipt.path()).unwrap());
    }
    let output_path = std::env::var("RUSTBGPD_PERSISTENCE_PHASE_OUTPUT")
        .expect("RUSTBGPD_PERSISTENCE_PHASE_OUTPUT is required");
    let output_path = Path::new(&output_path);
    retain_persistence_phase_receipt(output_path, &output);
    eprintln!("decision={:?}", verify_persistence_phase_receipt(&output));
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
    "min_hold_time",
    "slow_peer_threshold_pct",
    "slow_peer_duration",
    "slow_peer_isolation",
    "max_prefixes",
    "max_prefixes_out_ipv4",
    "max_prefixes_out_ipv6",
    "md5_password",
    "tcp_ao",
    "bfd",
    "ttl_security",
    "families",
    "required_families",
    "graceful_restart",
    "gr_peer_restart_time_max",
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
    "min_hold_time",
    "slow_peer_threshold_pct",
    "slow_peer_duration",
    "slow_peer_isolation",
    "max_prefixes",
    "max_prefixes_out_ipv4",
    "max_prefixes_out_ipv6",
    "md5_password",
    "bfd",
    "ttl_security",
    "families",
    "required_families",
    "graceful_restart",
    "gr_peer_restart_time_max",
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

fn reload_matrix_section<'a>(matrix: &'a str, start: &str, end: &str) -> &'a str {
    matrix
        .split_once(start)
        .unwrap_or_else(|| panic!("reload matrix is missing section {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("reload matrix section {start} is missing terminator {end}"))
        .0
}

/// All table rows in the reload matrix whose first cell is exactly the
/// backtick-wrapped field name. Returns every match — some knobs (e.g.
/// `log_level`) appear in both the `[[neighbors]]` and `[peer_groups]`
/// sections and must be classed consistently. Matching the exact
/// leading table-cell prefix avoids matching prose or compound cells
/// (such as the `tcp_ao mandatory fields` validation row).
fn reload_matrix_rows_for<'a>(matrix: &'a str, field: &str) -> Vec<&'a str> {
    let cell = format!("| `{field}` |");
    matrix
        .lines()
        .filter(|line| line.starts_with(&cell))
        .collect()
}

// ── ADR-0096: `.rpol` policy files in config ─────────────────────────

const RPOL_SOURCE: &str = r"
prefix-set customers { 10.10.0.0/16 ge 24 le 28 }

policy customer-in(peer_lp: u32) {
    term customer-routes {
        if route.prefix in customers { set local-pref peer_lp; accept }
    }
}

policy bogon-filter {
    term bogons { if route.prefix == 127.0.0.0/8 { reject } }
}
";

/// Write a config dir: `config.toml` + `policies/core.rpol`
/// (referenced by relative path), one neighbor with an rpol import
/// chain and one TOML-only neighbor. Returns the tempdir (keep alive).
fn rpol_config_dir(rpol_source: &str, chain: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), rpol_source).expect("write rpol");
    let toml = format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]

[policy.definitions.toml-pass]
default_action = "permit"

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = [{chain}]

[[neighbors]]
address = "192.0.2.2"
remote_asn = 65003
import_policy_chain = ["toml-pass"]
"#,
    );
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(&toml),
    )
    .expect("write config");
    dir
}

fn load_dir(dir: &tempfile::TempDir) -> Result<Config, String> {
    Config::load_with_diagnostics(dir.path().join("config.toml").to_str().unwrap())
}

/// Config dir with one `.rpol` unit and an optional
/// `rpol_max_graph_bytes` line, for graph-budget tests.
fn rpol_budget_config_dir(rpol_source: &str, budget_line: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), rpol_source).expect("write rpol");
    let toml = format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]
{budget_line}
import_chain = ["edge-in"]
"#,
    );
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(&toml),
    )
    .expect("write config");
    dir
}

const RPOL_BUDGET_POLICY: &str = "policy edge-in { term bogon { if route.prefix == 127.0.0.0/8 { reject } } term rest { accept } }\n";

// ── LAN-296: computed prepend operands at config attachment ─────────

/// A config dir whose neighbor binds `.rpol` chains in BOTH
/// directions, for direction-legality tests.
fn rpol_directional_config_dir(
    rpol_source: &str,
    import_chain: &str,
    export_chain: &str,
) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), rpol_source).expect("write rpol");
    let toml = format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = [{import_chain}]
export_policy_chain = [{export_chain}]
"#,
    );
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(&toml),
    )
    .expect("write config");
    dir
}

const PREPEND_OPERANDS_RPOL: &str = r"
policy peer-pad { term inbound-pad { prepend as peer 3; accept } }
policy self-pad { term outbound-pad { prepend as self 3; accept } }
policy origin-pad { term origin-pad { prepend as origin 2; accept } }
";

fn assert_raw_default_tier_rejected(error: &str) {
    assert!(
        error.contains("security.grpc.enforcement = \"tier\"")
            && error.contains("[security.grpc.roles]"),
        "raw config must reach production Tier validation: {error}"
    );
}

/// A raw config that fails default-Tier validation: a declared UDS
/// principal with no `[security.grpc.roles]` entry. Proves the
/// production loaders run Tier validation with no test-only bypass.
fn raw_tier_invalid_toml() -> String {
    format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml()
    )
}

fn raw_default_tier_config_file() -> NamedTempFile {
    let file = NamedTempFile::new().expect("temp config");
    fs::write(file.path(), raw_tier_invalid_toml()).expect("write raw config");
    file
}

// ─────────────────────────────────────────────────────────────────────
// External policy datasets (LAN-305)
// ─────────────────────────────────────────────────────────────────────

const DATASET_RPOL: &str = r"
dataset asn-set customers

policy origin-guard {
    term customers { if route.origin-as in customers { accept } }
    term rest { reject }
}
";

/// Config dir with an rpol-declared dataset bound to
/// `datasets/customers.list`. Returns the tempdir (keep alive).
fn dataset_config_dir(dataset_file: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::create_dir(dir.path().join("datasets")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), DATASET_RPOL).expect("write rpol");
    fs::write(dir.path().join("datasets/customers.list"), dataset_file).expect("write dataset");
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]

[policy.datasets.customers]
path = "datasets/customers.list"

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = ["origin-guard"]
"#;
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(toml),
    )
    .expect("write config");
    dir
}

fn origin_ctx(origin: u32) -> rustbgpd_policy::RouteContext<'static> {
    rustbgpd_policy::RouteContext {
        prefix: Some(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 0, 0, 0),
            24,
        ))),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: Some(origin),
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

// ── ADR-0112: RFC 8212 explicit policy on EBGP ──────────────────────
//
// Steps 1 and 2 of the ADR: directional explicit-policy provenance decided
// before the implicit tails, the reserved internal deny substitution, and the
// accept-any dynamic classification. The directional operator surface (status
// enum, metrics/explain attribution, doctor) is a later step and is not
// asserted here.

/// Build an ADR-0112 fixture from `[global]` extras, a policy block, the
/// neighbor's `remote_asn`, and neighbor-level extras.
fn rfc8212_toml(
    global_extra: &str,
    policy_block: &str,
    remote_asn: u32,
    neighbor_extra: &str,
) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
{global_extra}

[global.telemetry]
log_format = "json"
{policy_block}

[[neighbors]]
address = "10.0.0.2"
remote_asn = {remote_asn}
hold_time = 90
{neighbor_extra}
"#
    )
}

fn rfc8212_resolve(toml_str: &str) -> super::EffectivePolicyChains {
    let cfg = parse(toml_str).expect("ADR-0112 fixture parses");
    cfg.effective_policy_for_neighbor(&cfg.neighbors[0], false)
        .expect("ADR-0112 fixture resolves")
}

/// The reserved internal deny is a single daemon-owned member carrying the
/// documented attribution name and no operator content.
fn assert_reserved_deny(chain: Option<&PolicyChain>, expected_name: &str) {
    let chain = chain.expect("the reserved deny must be installed, not left permit-all");
    assert_eq!(
        chain
            .policies
            .iter()
            .map(|member| member.name.as_deref())
            .collect::<Vec<_>>(),
        vec![Some(expected_name)],
        "the reserved deny replaces the direction outright"
    );
    assert!(chain.policies[0].entries.is_empty());
    assert_eq!(chain.policies[0].default_action, PolicyAction::Deny);
}

fn assert_not_reserved_deny(chain: Option<&PolicyChain>) {
    if let Some(chain) = chain {
        assert!(
            !chain.policies.iter().any(|member| {
                matches!(
                    member.name.as_deref(),
                    Some(
                        super::RFC8212_MISSING_IMPORT_POLICY | super::RFC8212_MISSING_EXPORT_POLICY
                    )
                )
            }),
            "no reserved deny may appear in this direction"
        );
    }
}

mod dataplane;
mod datasets;
mod diff;
mod dynamic_neighbors;
mod evpn_instances;
mod evpn_ip_vrf;
mod evpn_segments;
mod examples;
mod families;
mod grpc_security;
mod gshut_blackhole;
mod neighbor_validation;
mod persistence;
mod policy_parsing;
mod rfc8212;
mod route_server;
mod rpki;
mod rpol;
mod telemetry;
mod transaction;
mod transport_auth;
