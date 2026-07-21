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
        // Strict parse (not the legacy-injecting `parse`) so every shipped
        // example is validated under the production v0.24.0
        // `enforcement = "tier"` default. Injection would mask examples that
        // cannot actually start under defaults — the gap that shipped all
        // examples unstartable until the v0.33.0 fixup. This guard fails
        // closed if a new example omits the gRPC authorization config.
        // Referenced .rpol files compile against the example's directory,
        // exactly like the production load path, so chains resolve against
        // the combined TOML + rpol namespace (e.g. route-server's
        // hygiene.rpol).
        let mut config: Config = toml::from_str(&source).unwrap_or_else(|err| {
            panic!("example config {label} failed to parse: {err}");
        });
        config.load_rpol_files(path.parent()).unwrap_or_else(|err| {
            panic!("example config {label} failed to load rpol files: {err}");
        });
        config.validate().unwrap_or_else(|err| {
            panic!("example config {label} failed validation under the tier default: {err}");
        });
    }
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

/// LAN-437 load-bearing proof: removing any retained IANA snapshot row or
/// parent exception changes its table row; breaking `rpol_files` or the chain
/// reference makes the real example fail to load. The ordinary-global and
/// 6to4 controls turn red if the starter expands into a blanket bogon filter.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the complete dated registry snapshot stays visible as one load-bearing table"
)]
fn route_server_example_special_purpose_snapshot() {
    let config = route_server_example_config();
    let neighbor = config
        .neighbors
        .first()
        .expect("route-server example has a neighbor");
    let (import, _) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("route-server example policy chains resolve");
    let import = import.expect("route-server example has an import chain");
    let member = import
        .policies
        .iter()
        .find(|member| member.name.as_deref() == Some("reject-special-purpose"))
        .expect("resolved import chain contains reject-special-purpose")
        .clone();
    let compiled = member
        .rpol
        .as_ref()
        .expect("special-purpose policy is .rpol-backed")
        .clone();
    let special_purpose = rustbgpd_policy::PolicyChain::from_named(vec![member]);

    let report = config.policy.rpol.policies["reject-special-purpose"]
        .file
        .run_tests();
    assert!(
        report.all_passed(),
        "route-server in-language policy tests failed: {:?}",
        report.failures
    );

    let rejected = [
        ("0.0.0.0/0", None, None, "0.0.0.0/0"),
        ("0.0.0.0/8", None, Some(32), "0.1.0.0/16"),
        ("10.0.0.0/8", None, Some(32), "10.1.0.0/16"),
        ("100.64.0.0/10", None, Some(32), "100.65.0.0/24"),
        ("127.0.0.0/8", None, Some(32), "127.1.0.0/16"),
        ("169.254.0.0/16", None, Some(32), "169.254.1.0/24"),
        ("172.16.0.0/12", None, Some(32), "172.17.0.0/16"),
        ("192.0.0.0/24", None, Some(32), "192.0.0.128/25"),
        ("192.0.2.0/24", None, Some(32), "192.0.2.0/25"),
        ("192.88.99.2/32", None, None, "192.88.99.2/32"),
        ("192.168.0.0/16", None, Some(32), "192.168.1.0/24"),
        ("198.18.0.0/15", None, Some(32), "198.18.1.0/24"),
        ("198.51.100.0/24", None, Some(32), "198.51.100.0/25"),
        ("203.0.113.0/24", None, Some(32), "203.0.113.0/25"),
        ("240.0.0.0/4", None, Some(32), "250.0.0.0/8"),
        ("::/0", None, None, "::/0"),
        ("::/128", None, None, "::/128"),
        ("::1/128", None, None, "::1/128"),
        ("::ffff:0:0/96", None, Some(128), "::ffff:192.0.2.0/120"),
        ("64:ff9b:1::/48", None, Some(128), "64:ff9b:1:1::/64"),
        ("100::/64", None, Some(128), "100::/65"),
        ("100:0:0:1::/64", None, Some(128), "100:0:0:1::/65"),
        ("2001::/23", None, Some(128), "2001:100::/32"),
        ("2001:db8::/32", None, Some(128), "2001:db8:1::/48"),
        ("3fff::/20", None, Some(128), "3fff:1::/32"),
        ("5f00::/16", None, Some(128), "5f00:1::/32"),
        ("fc00::/7", None, Some(128), "fd00:1::/48"),
        ("fe80::/10", None, Some(128), "fe80:1::/64"),
    ];
    assert_route_server_prefix_set(&compiled, "non-global-special-purpose", &rejected);
    for (prefix, _, _, probe) in rejected {
        let context = route_server_test_context(
            route_server_test_prefix(probe),
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
        );
        let (result, evaluation) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&special_purpose), &context);
        assert_eq!(
            result.action,
            rustbgpd_policy::PolicyAction::Deny,
            "retained snapshot row {prefix} must be rejected"
        );
        assert_eq!(
            evaluation.matched_policy.as_deref(),
            Some("reject-special-purpose"),
            "retained snapshot row {prefix} must attribute the rejection"
        );
    }

    let exceptions = [
        ("192.0.0.9/32", None, None, "192.0.0.9/32"),
        ("192.0.0.10/32", None, None, "192.0.0.10/32"),
        ("2001::/32", None, Some(128), "2001:0:1234::/48"),
        ("2001:1::1/128", None, None, "2001:1::1/128"),
        ("2001:1::2/128", None, None, "2001:1::2/128"),
        ("2001:1::3/128", None, None, "2001:1::3/128"),
        ("2001:3::/32", None, Some(128), "2001:3:1234::/48"),
        ("2001:4:112::/48", None, Some(128), "2001:4:112::1/128"),
        ("2001:20::/28", None, Some(128), "2001:20:abcd::/48"),
        ("2001:30::/28", None, Some(128), "2001:30:abcd::/48"),
    ];
    assert_route_server_prefix_set(&compiled, "special-purpose-parent-exceptions", &exceptions);
    for (prefix, _, _, probe) in exceptions {
        let context = route_server_test_context(
            route_server_test_prefix(probe),
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
        );
        let (result, _) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&special_purpose), &context);
        assert_eq!(
            result.action,
            rustbgpd_policy::PolicyAction::Permit,
            "active child {prefix} must precede and escape its rejected parent"
        );
    }

    for prefix in ["8.8.8.0/24", "2001:4860::/32", "2002::/16"] {
        let context = route_server_test_context(
            route_server_test_prefix(prefix),
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
        );
        let (result, _) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&special_purpose), &context);
        assert_eq!(
            result.action,
            rustbgpd_policy::PolicyAction::Permit,
            "out-of-snapshot control {prefix} must fall through"
        );
    }
}

/// LAN-437 load-bearing proof: the exact chain order keeps RPKI and ASPA
/// rejection ahead of parent exceptions and prefix-length caps after them.
/// Removing or reordering any member makes its attributed case fail; removing
/// the special-purpose member makes the representative/default cases permit.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one explicit matrix pins every ordered route-server import guard"
)]
fn route_server_example_exception_chain_preserves_later_guards() {
    let config = route_server_example_config();
    let neighbor = config
        .neighbors
        .first()
        .expect("route-server example has a neighbor");
    let (import, _) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("route-server example policy chains resolve");
    let import = import.expect("route-server example has an import chain");
    assert_eq!(
        import
            .policies
            .iter()
            .map(|member| member.name.as_deref().expect("every member is named"))
            .collect::<Vec<_>>(),
        [
            "reject-rpki-invalid",
            "ixp-hygiene",
            "reject-special-purpose",
            "reject-long-prefixes",
            "prefer-rpki-valid",
        ]
    );

    let cases = [
        (
            "0.0.0.0/0",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "::/0",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "100.65.0.0/24",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "fd00:1::/48",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "2001:4:112::/48",
            rustbgpd_wire::RpkiValidation::Invalid,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-rpki-invalid",
            None,
        ),
        (
            "2001::/32",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Invalid,
            rustbgpd_policy::PolicyAction::Deny,
            "ixp-hygiene",
            None,
        ),
        (
            "192.0.0.9/32",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-long-prefixes",
            None,
        ),
        (
            "2001:4:112::1/128",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-long-prefixes",
            None,
        ),
        (
            "2001:4:112::/48",
            rustbgpd_wire::RpkiValidation::Valid,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Permit,
            "prefer-rpki-valid",
            Some(200),
        ),
    ];
    for (prefix, rpki, aspa, action, matched_policy, local_pref) in cases {
        let context = route_server_test_context(route_server_test_prefix(prefix), rpki, aspa);
        let (result, evaluation) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&import), &context);
        assert_eq!(result.action, action, "unexpected decision for {prefix}");
        assert_eq!(
            evaluation.matched_policy.as_deref(),
            Some(matched_policy),
            "unexpected deciding policy for {prefix}"
        );
        assert_eq!(
            result.modifications.set_local_pref, local_pref,
            "unexpected local-pref modification for {prefix}"
        );
    }
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

const V1_EFFECTIVE_DEFAULTS_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

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

[security.grpc]
enforcement = "legacy"

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
fn slow_peer_knobs_parse_and_resolve() {
    let toml_str = valid_toml().replace(
        "remote_asn = 65002",
        "remote_asn = 65002\nslow_peer_threshold_pct = 25\nslow_peer_duration = 10\nslow_peer_isolation = true",
    );
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers[0].0.slow_peer_threshold_pct, 25);
    assert_eq!(peers[0].0.slow_peer_duration, 10);
    assert!(peers[0].0.slow_peer_isolation);
}

#[test]
fn slow_peer_defaults_applied() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(config.neighbors[0].slow_peer_threshold_pct, None);
    assert_eq!(config.neighbors[0].slow_peer_duration, None);
    assert_eq!(config.neighbors[0].slow_peer_isolation, None);

    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.slow_peer_threshold_pct,
        rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT
    );
    assert_eq!(
        peers[0].0.slow_peer_duration,
        rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS
    );
    assert!(!peers[0].0.slow_peer_isolation);
}

#[test]
fn slow_peer_threshold_zero_rejected() {
    let toml_str = valid_toml().replace(
        "remote_asn = 65002",
        "remote_asn = 65002\nslow_peer_threshold_pct = 0",
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidSlowPeerThreshold { value: 0 }
    ));
}

#[test]
fn slow_peer_threshold_over_100_rejected() {
    let toml_str = valid_toml().replace(
        "remote_asn = 65002",
        "remote_asn = 65002\nslow_peer_threshold_pct = 101",
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidSlowPeerThreshold { value: 101 }
    ));
}

#[test]
fn slow_peer_knobs_inherited_from_peer_group() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.clients]
slow_peer_threshold_pct = 30
slow_peer_duration = 15
slow_peer_isolation = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "clients"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "clients"
slow_peer_threshold_pct = 60
slow_peer_duration = 0
slow_peer_isolation = false
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    // First neighbor inherits the group values.
    assert_eq!(peers[0].0.slow_peer_threshold_pct, 30);
    assert_eq!(peers[0].0.slow_peer_duration, 15);
    assert!(peers[0].0.slow_peer_isolation);
    // Second neighbor overrides all three (0 = detection disabled).
    assert_eq!(peers[1].0.slow_peer_threshold_pct, 60);
    assert_eq!(peers[1].0.slow_peer_duration, 0);
    assert!(!peers[1].0.slow_peer_isolation);
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
    assert_eq!(
        config.warm_bundle_dir(),
        PathBuf::from("/var/lib/rustbgpd/warm-bundle-v1")
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
    assert_eq!(
        config.warm_bundle_dir(),
        PathBuf::from("/tmp/rustbgpd-test/warm-bundle-v1")
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
fn per_family_max_prefixes_inherit_from_group_and_override_per_neighbor() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ixp-members]
max_prefixes_ipv4 = 100
max_prefixes_ipv6 = 50

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
max_prefixes_ipv4 = 10
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.max_prefixes_ipv4,
        Some(10),
        "neighbor-level value overrides the group"
    );
    assert_eq!(
        peers[0].0.max_prefixes_ipv6,
        Some(50),
        "unset neighbor value inherits from the group"
    );
    assert_eq!(peers[0].0.max_prefixes, None, "aggregate stays independent");
}

/// Load-bearing: removing the peer-group fallback in `resolve_neighbor` makes
/// the first assertion read `None`; accepting plain `u32` makes the zero case
/// parse successfully instead of failing closed.
#[test]
fn max_prefix_restart_inherits_overrides_and_rejects_zero() {
    let inherited = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ixp-members]
max_prefix_restart_seconds = 30

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
"#;
    let config = parse(inherited).unwrap();
    let resolved = config.resolved_neighbors().unwrap();
    assert_eq!(resolved[0].max_prefix_restart_seconds, Some(30));

    let overridden = inherited.replace(
        "peer_group = \"ixp-members\"",
        "peer_group = \"ixp-members\"\nmax_prefix_restart_seconds = 10",
    );
    let config = parse(&overridden).unwrap();
    assert_eq!(
        config.resolved_neighbors().unwrap()[0].max_prefix_restart_seconds,
        Some(10)
    );

    let zero = inherited.replace(
        "max_prefix_restart_seconds = 30",
        "max_prefix_restart_seconds = 0",
    );
    assert!(
        parse(&zero).is_err(),
        "zero must not disable the opt-in action ambiguously"
    );
}

/// Load-bearing: removing the field from the hot-applicable classifier makes
/// this edit require a session rebuild instead of invalidating the old timer
/// through the in-place manager update.
#[test]
fn max_prefix_restart_edit_is_hot_applicable() {
    let old = test_neighbor("10.0.0.2", 65002);
    let mut hot = old.clone();
    hot.max_prefix_restart_seconds = std::num::NonZeroU32::new(30);
    assert!(super::neighbor_change_hot_applicable(&old, &hot));
    assert!(
        super::describe_neighbor_changes(&old, &hot)
            .iter()
            .any(|change| change.field == "max_prefix_restart_seconds")
    );
}

#[test]
fn per_family_max_prefix_edit_is_hot_applicable() {
    let old = test_neighbor("10.0.0.2", 65002);
    let mut hot = old.clone();
    hot.max_prefixes_ipv4 = Some(10);
    hot.max_prefixes_ipv6 = Some(20);
    assert!(super::neighbor_change_hot_applicable(&old, &hot));
    let changes = super::describe_neighbor_changes(&old, &hot);
    assert_eq!(changes.len(), 2);
    assert!(
        changes
            .iter()
            .all(|change| change.impact == Some(super::ConfigFieldImpact::HotApplied))
    );
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
    assert_eq!(
        peers[0]
            .0
            .md5_password
            .as_ref()
            .map(std::convert::AsRef::as_ref),
        Some("secret")
    );
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
    let tcp_ao = &tcp_ao.0[0];
    assert_eq!(tcp_ao.key, "secret");
    assert_eq!(tcp_ao.send_id, 7);
    assert_eq!(tcp_ao.recv_id, 9);
    assert_eq!(tcp_ao.algorithm, "hmac(sha256)");
    assert!(tcp_ao.preferred);
    assert!(!tcp_ao.deprecated);

    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.md5_password.is_none());
    let runtime_tcp_ao = peers[0].0.tcp_ao.as_ref().unwrap();
    let runtime_tcp_ao = &runtime_tcp_ao.0[0];
    assert_eq!(runtime_tcp_ao.key.as_ref(), "secret");
    assert_eq!(runtime_tcp_ao.send_id, 7);
    assert_eq!(runtime_tcp_ao.recv_id, 9);
    assert_eq!(
        runtime_tcp_ao.algorithm,
        rustbgpd_transport::TcpAoAlgorithm::HmacSha256
    );
}

#[test]
fn tcp_ao_keyring_accepts_legacy_singleton_and_preserves_ordered_multi_key_shape() {
    #[derive(serde::Deserialize)]
    struct Holder {
        tcp_ao: TcpAoKeyringConfig,
    }
    let singleton = toml::from_str::<Holder>(
        r#"[tcp_ao]
key = "legacy"
send_id = 7
recv_id = 9
algorithm = "hmac(sha256)"
"#,
    )
    .unwrap()
    .tcp_ao;
    assert_eq!(singleton.0.len(), 1);
    assert_eq!(singleton.0[0].key, "legacy");
    let singleton_value = toml::Value::try_from(&singleton).unwrap();
    assert!(
        singleton_value.is_table(),
        "singleton must serialize as legacy table"
    );

    let ordered = toml::from_str::<Holder>(
        r#"tcp_ao = [
{ key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)", deprecated = true },
{ key = "next", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true }
]"#,
    )
    .unwrap()
    .tcp_ao;
    assert_eq!(
        ordered
            .0
            .iter()
            .map(|key| key.key.as_str())
            .collect::<Vec<_>>(),
        ["old", "next"]
    );
    let ordered_value = toml::Value::try_from(&ordered).unwrap();
    assert!(
        ordered_value.is_array(),
        "multi-key ring must serialize as an array"
    );
}

#[test]
fn tcp_ao_keyring_validation_rejects_ambiguous_or_unselectable_rings() {
    let cases = [
        ("[]", "1..=256"),
        (
            r#"[
{ key = "one", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" },
{ key = "two", send_id = 1, recv_id = 12, algorithm = "hmac(sha256)" }
]"#,
            "duplicate SendID",
        ),
        (
            r#"[
{ key = "one", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" },
{ key = "two", send_id = 2, recv_id = 11, algorithm = "hmac(sha256)" }
]"#,
            "duplicate RecvID",
        ),
        (
            r#"[
{ key = "one", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)", preferred = true },
{ key = "two", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true }
]"#,
            "at most one key",
        ),
        (
            r#"[
{ key = "one", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)", deprecated = true }
]"#,
            "at least one key must not be deprecated",
        ),
    ];
    for (ring, expected) in cases {
        let source = format!(
            r#"[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = {ring}
"#
        );
        let error = parse(&source).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn tcp_ao_keyring_order_and_metadata_reach_transport_unchanged() {
    let config = parse(
        r#"[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)", deprecated = true },
  { key = "next", send_id = 2, recv_id = 12, algorithm = "cmac(aes128)", preferred = true }
]
"#,
    )
    .unwrap();
    let peers = config.to_peer_configs().unwrap();
    let ring = peers[0].0.tcp_ao.as_ref().unwrap();
    assert_eq!(ring.0.len(), 2);
    assert_eq!((ring.0[0].send_id, ring.0[0].deprecated), (1, true));
    assert_eq!((ring.0[1].recv_id, ring.0[1].preferred), (12, true));
    assert_eq!(ring.selected().unwrap().send_id, 2);
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

#[test]
fn tcp_ao_listener_capacity_is_bounded_independently_per_address_family() {
    let mut config = parse(valid_toml()).unwrap();
    config.neighbors.clear();
    for owner_index in 1..=16 {
        if owner_index <= 15 {
            let mut ipv4 = test_neighbor(&format!("192.0.2.{owner_index}"), 65002);
            ipv4.tcp_ao = Some(tcp_ao_test_keyring(256));
            config.neighbors.push(ipv4);
        }

        let mut ipv6 = test_neighbor(&format!("2001:db8::{owner_index}"), 65002);
        ipv6.tcp_ao = Some(tcp_ao_test_keyring(256));
        config.neighbors.push(ipv6);
    }
    config
        .peer_groups
        .insert("dynamic-ao".to_string(), PeerGroupConfig::default());
    config.dynamic_neighbors.push(DynamicNeighborConfig {
        prefix: "198.51.100.0/24".to_string(),
        peer_group: "dynamic-ao".to_string(),
        remote_asn: 65002,
        description: None,
        tcp_ao: Some(tcp_ao_test_keyring(256)),
    });
    config
        .validate()
        .expect("4,096 MKTs in each address family must remain valid");

    let mut over_limit = test_neighbor("192.0.2.250", 65002);
    over_limit.tcp_ao = Some(tcp_ao_test_keyring(1));
    config.neighbors.push(over_limit);
    let err = config
        .validate()
        .expect_err("4,097 IPv4 listener MKTs must be rejected");
    match err {
        ConfigError::InvalidNeighborConfig {
            address,
            field,
            reason,
        } => {
            assert_eq!(address, "IPv4 BGP listener");
            assert_eq!(field, "tcp_ao");
            assert!(reason.contains("4097"), "{reason}");
            assert!(reason.contains("4096"), "{reason}");
        }
        other => panic!("expected aggregate TCP-AO listener error, got {other}"),
    }
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

[policy]
import_chain = ["import-filter"]
export_chain = ["export-filter"]

[policy.definitions.import-filter]
[[policy.definitions.import-filter.statements]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 24
le = 32

[policy.definitions.export-filter]
[[policy.definitions.export-filter.statements]]
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

[policy]
export_chain = ["deny-tens"]

[policy.definitions.deny-tens]
[[policy.definitions.deny-tens.statements]]
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

[policy]
export_chain = ["deny-tens"]

[policy.definitions.deny-tens]
[[policy.definitions.deny-tens.statements]]
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
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
fn gr_peer_restart_time_max_outside_wire_range_rejected() {
    // Load-bearing: deleting either boundary validation makes one case load.
    for value in [0, 4096] {
        let err = parse(&gr_toml(&format!("gr_peer_restart_time_max = {value}"))).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidGrConfig { .. }));
    }
}

#[test]
fn gr_peer_restart_time_max_peer_group_only_bounds_rejected() {
    let base = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.rr]
"#;

    // Load-bearing: these groups have no members, so removing the dedicated
    // validate_peer_group bounds branch makes both invalid configs load.
    for value in [0, 4096] {
        let err = parse(&format!("{base}gr_peer_restart_time_max = {value}\n")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidGrConfig { .. }));
    }
}

#[test]
fn gr_peer_restart_time_max_neighbor_overrides_peer_group() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.rr]
gr_peer_restart_time_max = 900

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rr"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rr"
gr_peer_restart_time_max = 300
"#;
    let config = parse(toml).unwrap();

    // Load-bearing: removing group fallback makes the first value 4095;
    // making the group outrank the neighbor makes the second value 900.
    assert_eq!(
        config
            .resolve_neighbor(&config.neighbors[0])
            .unwrap()
            .transport_config
            .gr_peer_restart_time_max,
        900
    );
    assert_eq!(
        config
            .resolve_neighbor(&config.neighbors[1])
            .unwrap()
            .transport_config
            .gr_peer_restart_time_max,
        300
    );
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

#[test]
fn bgpls_families_parse_to_linkstate_afi_safis() {
    let toml = gr_toml(r#"families = ["linkstate", "linkstate_vpn"]"#);
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.peer.families,
        vec![(Afi::BgpLs, Safi::BgpLs), (Afi::BgpLs, Safi::BgpLsVpn)]
    );
}

#[test]
fn l3vpn_families_parse_to_mpls_vpn_afi_safis() {
    let toml = gr_toml(r#"families = ["l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast"]"#);
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.peer.families,
        vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv6, Safi::MplsVpn)]
    );
}

#[test]
fn labeled_families_parse_to_labeled_unicast_afi_safis() {
    let toml = gr_toml(r#"families = ["ipv4_labeled_unicast", "ipv6_labeled_unicast"]"#);
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.peer.families,
        vec![
            (Afi::Ipv4, Safi::LabeledUnicast),
            (Afi::Ipv6, Safi::LabeledUnicast)
        ]
    );
}

#[test]
fn rtc_family_parses_to_ipv4_rt_constrain() {
    let toml = gr_toml(r#"families = ["l3vpn_ipv4_unicast", "rtc"]"#);
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.peer.families,
        vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv4, Safi::RtConstrain)]
    );
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

#[test]
fn orr_vantage_inherits_from_peer_group() {
    let toml = orr_toml(
        "",
        "route_reflector_client = true\norr_vantage = \"192.0.2.7\"",
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.neighbors[0].orr_vantage, None);
    let resolved = config.resolved_neighbors().unwrap();
    assert_eq!(
        resolved[0].transport_config.orr_vantage,
        Some("192.0.2.7".parse().unwrap()),
        "group vantage inherited into the transport config"
    );
}

#[test]
fn orr_vantage_neighbor_overrides_group() {
    let toml = orr_toml(
        "orr_vantage = \"192.0.2.9\"",
        "route_reflector_client = true\norr_vantage = \"192.0.2.7\"",
    );
    let config = parse(&toml).unwrap();
    let resolved = config.resolved_neighbors().unwrap();
    assert_eq!(
        resolved[0].transport_config.orr_vantage,
        Some("192.0.2.9".parse().unwrap()),
        "neighbor vantage wins over the group's"
    );

    // Persister-shaped round-trip: a Some(IpAddr) vantage survives TOML
    // serialize → re-parse (the config-persister write path).
    let rendered = toml::to_string_pretty(&config).unwrap();
    let reparsed = parse(&rendered).unwrap();
    assert_eq!(
        reparsed.neighbors[0].orr_vantage,
        Some("192.0.2.9".parse().unwrap())
    );
}

#[test]
fn orr_vantage_rejected_without_rr_client() {
    let toml = orr_toml("orr_vantage = \"192.0.2.7\"", "");
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
    assert!(
        err.to_string().contains("orr_vantage"),
        "diagnostic names the field: {err}"
    );
}

#[test]
fn orr_vantage_rejected_on_ebgp() {
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
orr_vantage = "192.0.2.7"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
    assert!(
        err.to_string().contains("requires iBGP"),
        "diagnostic names the eBGP conflict: {err}"
    );
}

#[test]
fn orr_vantage_rejected_when_equal_to_neighbor_or_local_address() {
    // Vantage == the neighbor's own peering address (10.0.0.2).
    let toml = orr_toml(
        "route_reflector_client = true\norr_vantage = \"10.0.0.2\"",
        "",
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
    assert!(
        err.to_string().contains("orr_vantage")
            && err.to_string().contains("neighbor's own address"),
        "diagnostic names the field and offending address: {err}"
    );

    // Vantage == the reflector's own router_id (10.0.0.1).
    let toml = orr_toml(
        "route_reflector_client = true\norr_vantage = \"10.0.0.1\"",
        "",
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
    assert!(
        err.to_string().contains("orr_vantage") && err.to_string().contains("router_id"),
        "diagnostic names the field and offending address: {err}"
    );

    // A distinct vantage is still accepted.
    let toml = orr_toml(
        "route_reflector_client = true\norr_vantage = \"192.0.2.7\"",
        "",
    );
    assert!(parse(&toml).is_ok(), "distinct vantage passes validation");
}

#[test]
fn orr_vantage_rejected_when_unspecified_or_loopback() {
    // Wildcard (0.0.0.0 / ::) and loopback vantages name no real BGP-LS
    // topology node — reject at load rather than run inert ORR.
    for degenerate in ["0.0.0.0", "::", "127.0.0.1", "::1"] {
        let toml = orr_toml(
            &format!("route_reflector_client = true\norr_vantage = \"{degenerate}\""),
            "",
        );
        let err = parse(&toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidRrConfig { .. })
                && err.to_string().contains("unspecified or loopback"),
            "degenerate vantage {degenerate} must be rejected: {err:?}"
        );
    }
}

#[test]
fn orr_vantage_warns_without_linkstate_family() {
    // The warning condition (pure helper backing the load-time warn):
    // vantage set, no linkstate family anywhere → true.
    let toml = orr_toml(
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true",
        "",
    );
    let config = parse(&toml).unwrap();
    assert!(config.orr_vantage_without_linkstate());

    // Any neighbor with the linkstate family (even another one — it is
    // the topology FEED, not the vantage carrier) clears the warning.
    let toml = orr_toml(
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true\nfamilies = [\"ipv4_unicast\", \"linkstate\"]",
        "",
    );
    let config = parse(&toml).unwrap();
    assert!(!config.orr_vantage_without_linkstate());

    // A linkstate family inherited from a group counts too.
    let toml = orr_toml(
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true",
        "families = [\"linkstate\"]",
    );
    let config = parse(&toml).unwrap();
    assert!(!config.orr_vantage_without_linkstate());

    // No vantage anywhere → no warning regardless of families.
    let config = parse(&orr_toml("", "")).unwrap();
    assert!(!config.orr_vantage_without_linkstate());
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
fn per_client_best_requires_route_server_client() {
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
per_client_best = true
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouteServerConfig { .. }));
}

#[test]
fn per_client_best_with_route_server_client_accepted() {
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
per_client_best = true
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].per_client_best, Some(true));
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.per_client_best);
}

#[test]
fn per_client_best_inherits_from_peer_group() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ixp-members]
route_server_client = true
per_client_best = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.route_server_client);
    assert!(peers[0].0.per_client_best);
}

#[test]
fn next_hop_ownership_requires_route_server_client() {
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
next_hop_ownership = "strict_peer"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouteServerConfig { .. }));
}

#[test]
fn next_hop_ownership_strict_peer_parses_and_reaches_transport() {
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
next_hop_ownership = "strict_peer"
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(
        config.neighbors[0].next_hop_ownership,
        Some(NextHopOwnershipConfig::StrictPeer)
    );
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.next_hop_ownership_strict_peer);
}

/// ADR-0107 default: unset means no ownership enforcement — a plain
/// route-server client stays transparent-but-unchecked.
#[test]
fn next_hop_ownership_defaults_off_for_route_server_clients() {
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
    assert_eq!(config.neighbors[0].next_hop_ownership, None);
    let peers = config.to_peer_configs().unwrap();
    assert!(!peers[0].0.next_hop_ownership_strict_peer);
}

#[test]
fn next_hop_ownership_inherits_from_peer_group() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ixp-members]
route_server_client = true
next_hop_ownership = "strict_peer"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.route_server_client);
    assert!(peers[0].0.next_hop_ownership_strict_peer);
}

#[test]
fn next_hop_ownership_from_group_without_route_server_client_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ixp-members]
next_hop_ownership = "strict_peer"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouteServerConfig { .. }));
}

/// The deferred ADR-0107 modes (`same_as`, `explicit_authorized`) are
/// not valid configuration until the fleet-inventory prerequisite ships;
/// the enum is closed so an unknown mode fails at parse.
#[test]
fn next_hop_ownership_rejects_unshipped_modes() {
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
next_hop_ownership = "same_as"
"#;
    assert!(parse(toml_str).is_err());
}

#[test]
fn interpret_rfc1997_defaults_true_for_plain_peers_false_for_rs_clients() {
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

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
route_server_client = true

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
route_server_client = true
interpret_rfc1997 = true

[[neighbors]]
address = "10.0.0.5"
remote_asn = 65005
interpret_rfc1997 = false
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    // Plain eBGP: honor RFC 1997 by default.
    assert!(peers[0].0.interpret_rfc1997);
    // Route-server client: transparent by default.
    assert!(!peers[1].0.interpret_rfc1997);
    // Explicit opt-in on an RS client overrides the derived default.
    assert!(peers[2].0.interpret_rfc1997);
    // Explicit opt-out on a plain peer overrides the derived default.
    assert!(!peers[3].0.interpret_rfc1997);
}

#[test]
fn interpret_rfc1997_inherits_from_peer_group_and_derives_from_group_rs_flag() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.transit]
interpret_rfc1997 = false

[peer_groups.ixp-members]
route_server_client = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "transit"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "ixp-members"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
peer_group = "ixp-members"
interpret_rfc1997 = true
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    // Group-level explicit value inherits.
    assert!(!peers[0].0.interpret_rfc1997);
    // Group-level route_server_client drives the derived default.
    assert!(peers[1].0.route_server_client);
    assert!(!peers[1].0.interpret_rfc1997);
    // Neighbor-level override beats both.
    assert!(peers[2].0.interpret_rfc1997);
}

#[test]
fn per_client_best_from_group_without_route_server_client_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ixp-members]
per_client_best = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouteServerConfig { .. }));
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
fn set_route_communities_use_rfc_admin_specific_encodings_for_add_and_remove() {
    // Red proof: routing numeric AS4 or dotted-IPv4 administrators through the
    // old type-0x00-only TOML builders makes the exact byte matrix fail (or
    // rejects the AS4 values); dropping original spelling makes the IPv4 rows
    // become type 0x02, and wiring only add or remove breaks the parity assert.
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = [
                "RT:65001:100", "RO:65001:200",
                "RT:100000:100", "RO:100000:200",
                "RT:192.0.2.1:100", "RO:192.0.2.1:200",
                "RT:65535:70000"
            ]
            set_community_remove = [
                "RT:65001:100", "RO:65001:200",
                "RT:100000:100", "RO:100000:200",
                "RT:192.0.2.1:100", "RO:192.0.2.1:200",
                "RT:65535:70000"
            ]"#,
    );
    let cfg = parse(&toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let statement = &import.expect("import chain configured").policies[0].entries[0];
    let expected = vec![
        0x0002_FDE9_0000_0064,
        0x0003_FDE9_0000_00C8,
        0x0202_0001_86A0_0064,
        0x0203_0001_86A0_00C8,
        0x0102_C000_0201_0064,
        0x0103_C000_0201_00C8,
        0x0002_FFFF_0001_1170,
    ];
    let added: Vec<u64> = statement
        .modifications
        .extended_communities_add
        .iter()
        .map(|community| community.as_u64())
        .collect();
    let removed: Vec<u64> = statement
        .modifications
        .extended_communities_remove
        .iter()
        .map(|community| community.as_u64())
        .collect();
    assert_eq!(added, expected);
    assert_eq!(removed, expected);
}

#[test]
fn set_route_community_rejects_as4_local_that_exceeds_u16() {
    // Red proof: deleting `parse_community_match`'s AS4 local-width check
    // routes the invalid value to the shared encoder, changing this exact
    // parser diagnostic and failing the equality assertion below.
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = ["RT:100000:70000"]"#,
    );
    let ConfigError::InvalidPolicyEntry { reason } = parse(&toml).unwrap_err() else {
        panic!("expected invalid policy entry")
    };
    assert_eq!(
        reason,
        "invalid local admin 70000: exceeds 65535 for 4-octet ASN 100000"
    );
}

#[test]
fn set_route_community_rejects_ipv4_local_that_exceeds_u16() {
    // Red proof: deleting `parse_community_match`'s dotted-IPv4 local-width
    // check routes the invalid value to the shared encoder and changes this
    // exact parser diagnostic; treating the spelling as an ASN also changes
    // the administrator kind.
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_remove = ["RO:192.0.2.1:70000"]"#,
    );
    let ConfigError::InvalidPolicyEntry { reason } = parse(&toml).unwrap_err() else {
        panic!("expected invalid policy entry")
    };
    assert_eq!(
        reason,
        "invalid local admin 70000: exceeds 65535 for IPv4 global administrator 192.0.2.1"
    );
}

#[test]
fn ov_well_known_ext_community_names_in_toml_policy() {
    // RFC 8097 origin-validation states ride the well-known-name path
    // in match and set positions.
    let toml = community_toml(
        r#"action = "permit"
            match_community = ["OV_INVALID"]
            set_community_add = ["OV_VALID"]
            set_community_remove = ["OV_NOT_FOUND"]"#,
    );
    let cfg = parse(&toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("import chain configured");
    let stmt = &chain.policies[0].entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::ExactExt(
            rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_INVALID.as_u64()
        )]
    );
    assert_eq!(
        stmt.modifications.extended_communities_add,
        vec![rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_VALID]
    );
    assert_eq!(
        stmt.modifications.extended_communities_remove,
        vec![rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_NOT_FOUND]
    );
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
receive_max = 3
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.add_path_receive);
    assert_eq!(peers[0].0.peer.paths_limit_receive_max, 3);
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
fn required_families_inherit_and_neighbor_nonempty_override_is_validated() {
    // Load-bearing: changing resolution to union/group-first makes the first
    // peer inherit IPv6 despite its non-empty IPv4 override; removing subset
    // validation lets the second, impossible peer load.
    let valid = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[peer_groups.fabric]
families = ["ipv4_unicast", "ipv6_unicast"]
required_families = ["ipv6_unicast"]
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "fabric"
required_families = ["ipv4_unicast"]
"#;
    let config = parse(valid).unwrap();
    assert_eq!(
        config.to_peer_configs().unwrap()[0]
            .0
            .peer
            .required_families,
        vec![(Afi::Ipv4, Safi::Unicast)]
    );

    let invalid = valid.replace(
        "required_families = [\"ipv4_unicast\"]",
        "families = [\"ipv4_unicast\"]",
    );
    let err = parse(&invalid).unwrap_err();
    assert!(err.to_string().contains("required_families"), "{err}");
}

#[test]
fn required_families_validate_after_disable_ipv4_unicast() {
    // Load-bearing: validating against raw configured families before the
    // IPv4 suppression would accept a requirement the session can never meet.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[[neighbors]]
address = "2001:db8::2"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast"]
required_families = ["ipv4_unicast"]
disable_ipv4_unicast = true
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("required_families"), "{err}");
}

#[test]
fn dynamic_ipv4_default_rejects_inherited_ipv6_requirement() {
    // Load-bearing: skipping representative-address validation for dynamic
    // ranges would accept this IPv4 range even though its default family set
    // cannot satisfy the inherited IPv6 requirement.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[peer_groups.dynamic]
required_families = ["ipv6_unicast"]
[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "dynamic"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("required family"), "{err}");
}

#[test]
fn unreferenced_group_can_defer_address_dependent_required_family_validation() {
    // Load-bearing: blindly treating an empty group family list as IPv4 would
    // reject this reusable definition before an address-bearing consumer exists.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[peer_groups.future_ipv6]
required_families = ["ipv6_unicast"]
"#;
    parse(toml).unwrap();
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
    assert_eq!(
        bmp.collectors[0].monitor,
        vec![BmpMonitorView::RibInPre],
        "default monitor selection is pre-RFC 8671 rib-in only"
    );
}

#[test]
fn bmp_monitor_rib_out_post_accepted() {
    let config = parse(&bmp_toml(r#"monitor = ["rib_in_pre", "rib_out_post"]"#)).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(
        bmp.collectors[0].monitor,
        vec![BmpMonitorView::RibInPre, BmpMonitorView::RibOutPost]
    );
}

#[test]
fn bmp_monitor_loc_rib_accepted() {
    let config = parse(&bmp_toml(r#"monitor = ["loc_rib"]"#)).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(
        bmp.collectors[0].monitor,
        vec![BmpMonitorView::LocRib],
        "RFC 9069 Loc-RIB view is selectable on its own"
    );
}

#[test]
fn bmp_empty_monitor_rejected() {
    let err = parse(&bmp_toml("monitor = []")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}

#[test]
fn bmp_unknown_monitor_value_rejected() {
    assert!(parse(&bmp_toml(r#"monitor = ["rib_out_pre"]"#)).is_err());
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
fn bmp_version_defaults_to_3() {
    let config = parse(&bmp_toml("")).unwrap();
    assert_eq!(
        config.bmp.as_ref().unwrap().collectors[0].version,
        3,
        "BMP wire version defaults to RFC 7854 v3"
    );
}

#[test]
fn bmp_version_4_accepted() {
    let config = parse(&bmp_toml("version = 4")).unwrap();
    assert_eq!(config.bmp.as_ref().unwrap().collectors[0].version, 4);
}

#[test]
fn bmp_invalid_version_rejected() {
    for bad in ["version = 2", "version = 5"] {
        let err = parse(&bmp_toml(bad)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
    }
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

#[test]
fn gnmi_dialout_valid_config_accepted_with_defaults() {
    let config = parse(&gnmi_dialout_toml("")).unwrap();
    let section = config.gnmi_dialout.as_ref().unwrap();
    assert_eq!(section.targets.len(), 1);
    let target = &section.targets[0];
    assert_eq!(target.name, "collector-a");
    assert_eq!(target.mode, GnmiDialoutModeConfig::Sample);
    assert_eq!(target.sample_interval, 10);
    assert_eq!(target.backoff_initial, 1);
    assert_eq!(target.backoff_max, 30);
    assert!(target.tls_ca_file.is_none());

    let targets = super::gnmi_dialout_targets(&config).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].endpoint, "http://192.0.2.10:57400",
        "no TLS section dials plaintext"
    );
}

#[test]
fn gnmi_dialout_tls_target_builds_https_endpoint() {
    let config = parse(&gnmi_dialout_toml(
        "tls_ca_file = \"/etc/rustbgpd/collector-ca.pem\"\n\
         tls_cert_file = \"/etc/rustbgpd/client.pem\"\n\
         tls_key_file = \"/etc/rustbgpd/client.key\"\n\
         tls_server_name = \"collector.example\"",
    ))
    .unwrap();
    let targets = super::gnmi_dialout_targets(&config).unwrap();
    assert_eq!(targets[0].endpoint, "https://192.0.2.10:57400");
    let tls = targets[0].tls.as_ref().unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("collector.example"));
}

#[test]
fn gnmi_dialout_duplicate_target_name_rejected() {
    let toml = gnmi_dialout_toml("")
        + "\n[[gnmi_dialout.targets]]\nname = \"collector-a\"\naddress = \"192.0.2.11:57400\"\npaths = [\"network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state/as\"]\n";
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_invalid_address_rejected() {
    for bad in ["no-port", ":57400", "192.0.2.10:notaport", ""] {
        let err = parse(&gnmi_dialout_toml("").replace("192.0.2.10:57400", bad)).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidGnmiDialout { .. }),
            "expected InvalidGnmiDialout for address {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn gnmi_dialout_empty_paths_rejected() {
    let toml = gnmi_dialout_toml("").replace(
        &format!("paths = [\"{DIALOUT_SESSION_STATE_PATH}\"]"),
        "paths = []",
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_unsupported_path_rejected() {
    // The same validation a dial-in Subscribe would apply: paths outside
    // the supported OpenConfig BGP surface fail at config load.
    let toml = gnmi_dialout_toml("").replace(
        DIALOUT_SESSION_STATE_PATH,
        "interfaces/interface[name=eth0]/state",
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_tls_pairing_rules_enforced() {
    // Cert without key.
    let err = parse(&gnmi_dialout_toml(
        "tls_ca_file = \"/etc/ca.pem\"\ntls_cert_file = \"/etc/client.pem\"",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
    // Cert+key without CA.
    let err = parse(&gnmi_dialout_toml(
        "tls_cert_file = \"/etc/client.pem\"\ntls_key_file = \"/etc/client.key\"",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
    // Server-name override without CA (no TLS at all).
    let err = parse(&gnmi_dialout_toml(
        "tls_server_name = \"collector.example\"",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_on_change_requires_event_history() {
    let err = parse(&gnmi_dialout_toml("mode = \"on_change\"")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));

    // With the durable outbox enabled, ON_CHANGE on the session-state
    // leaf is accepted.
    let toml = format!(
        "{}\n[event_history]\nenabled = true\n",
        gnmi_dialout_toml("mode = \"on_change\"")
    );
    parse(&toml).unwrap();
}

#[test]
fn gnmi_dialout_on_change_unsupported_leaf_rejected() {
    // ON_CHANGE is only supported on the session-state leaf, exactly like
    // dial-in Subscribe.
    let toml = format!(
        "{}\n[event_history]\nenabled = true\n",
        gnmi_dialout_toml("mode = \"on_change\"").replace(
            DIALOUT_SESSION_STATE_PATH,
            "network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state/as",
        )
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_timer_bounds_enforced() {
    for bad in [
        "sample_interval = 0",
        "backoff_initial = 0",
        "backoff_initial = 10\nbackoff_max = 5",
    ] {
        let err = parse(&gnmi_dialout_toml(bad)).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidGnmiDialout { .. }),
            "expected InvalidGnmiDialout for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn gnmi_dialout_unknown_field_rejected() {
    assert!(parse(&gnmi_dialout_toml("bogus_field = true")).is_err());
}

#[test]
fn gnmi_dialout_absent_section_yields_no_targets() {
    let toml = gnmi_dialout_toml("");
    let stripped = toml.split("[gnmi_dialout]").next().unwrap();
    let config = parse(stripped).unwrap();
    assert!(config.gnmi_dialout.is_none());
    assert!(super::gnmi_dialout_targets(&config).unwrap().is_empty());
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
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
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
    new_neighbor.tcp_ao = Some(
        TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: true,
            deprecated: false,
        }
        .into(),
    );

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
        changes
            .iter()
            .any(|c| c.render().contains("prefix_orf_receive")),
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
        changes
            .iter()
            .any(|c| c.render().contains("disable_ipv4_unicast")),
        "describe_neighbor_changes must name disable_ipv4_unicast, got {changes:?}"
    );
}

#[test]
fn diff_config_flags_tcp_ao_changes_as_restart_required() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "old-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );
    let mut new = old.clone();
    new.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "new-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

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
fn resolve_neighbor_threads_reject_retention_settings() {
    // LAN-472: the resolved-neighbor transport path must thread the
    // [policy.reject_retention] knobs, mirroring the [policy.explain]
    // threading above.
    let mut config = parse(valid_toml()).unwrap();
    config.policy.reject_retention.enabled = false;
    config.policy.reject_retention.capacity = 64;
    let resolved = config.resolve_neighbor(&config.neighbors[0]).unwrap();
    assert!(
        !resolved.transport_config.reject_retention_enabled,
        "enabled must propagate through resolve_neighbor"
    );
    assert_eq!(resolved.transport_config.reject_retention_capacity, 64);
}

#[test]
fn diff_config_flags_reject_retention_as_restart_required() {
    // LAN-472: a [policy.reject_retention] edit is restart-required-per-
    // peer and must be visible in `--diff` (JSON + text), matching the
    // [policy.explain] contract.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.policy.reject_retention.enabled = false;
    new.policy.reject_retention.capacity = 128;

    let diff = super::diff_config(&old, &new);
    assert!(diff.policy_reject_retention_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "a reject-retention-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["restart_required"]["policy_reject_retention_changed"],
        true
    );

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[policy.reject_retention]"), "{text}");
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
fn diff_config_flags_security_grpc_as_restart_required() {
    // LAN-286: `[security.grpc]` is resolved once at startup when the
    // gRPC listeners are built — an edit must classify as
    // restart-required, not vanish from the diff.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.security
        .grpc
        .roles
        .insert("observer-readonly".to_string(), GrpcRoleConfig::Observer);

    let diff = super::diff_config(&old, &new);
    assert!(diff.security_grpc_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "a security-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["security_grpc_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[security.grpc]"), "{text}");

    let sections = super::classify_config_transaction_v1(&diff);
    assert!(
        sections
            .restart_required_sections
            .contains(&"[security.grpc]".to_string()),
        "{sections:?}"
    );
}

#[test]
fn diff_config_flags_event_history_as_restart_required() {
    // LAN-286: every `[event_history]` field is restart-required (the
    // ADR-0072 outbox is configured once at startup) — an edit must
    // classify as restart-required, not vanish from the diff.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.event_history.enabled = !new.event_history.enabled;

    let diff = super::diff_config(&old, &new);
    assert!(diff.event_history_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "an event-history-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["event_history_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[event_history]"), "{text}");

    let sections = super::classify_config_transaction_v1(&diff);
    assert!(
        sections
            .restart_required_sections
            .contains(&"[event_history]".to_string()),
        "{sections:?}"
    );
}

#[test]
fn diff_config_pins_entire_neighbor_when_tcp_ao_changes() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].hold_time = Some(90);
    old.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "old-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );
    let mut new = old.clone();
    new.neighbors[0].hold_time = Some(120);
    new.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "new-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

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
        neighbor
            .tcp_ao
            .as_ref()
            .map(|tcp_ao| tcp_ao.0[0].key.as_str()),
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
            send_hold_time: None,
            slow_peer_threshold_pct: None,
            slow_peer_duration: None,
            slow_peer_isolation: None,
            max_prefixes: None,
            max_prefixes_ipv4: None,
            max_prefixes_ipv6: None,
            max_prefix_restart_seconds: None,
            md5_password: None,
            ttl_security: None,
            bfd: None,
            families: Vec::new(),
            required_families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_peer_restart_time_max: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            orr_vantage: None,
            route_server_client: None,
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
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        bfd: None,
        tcp_ao: Some(
            TcpAoConfig {
                key: "secret".into(),
                send_id: 1,
                recv_id: 1,
                algorithm: "hmac(sha256)".into(),
                preferred: false,
                deprecated: false,
            }
            .into(),
        ),
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
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
    });
    new.neighbors.push(Neighbor {
        address: "10.0.0.4".into(),
        interface: None,
        remote_asn: 65004,
        description: None,
        peer_group: Some("new-group".into()),
        hold_time: None,
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
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
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        bfd: None,
        tcp_ao: Some(
            TcpAoConfig {
                key: "secret".into(),
                send_id: 1,
                recv_id: 1,
                algorithm: "hmac(sha256)".into(),
                preferred: false,
                deprecated: false,
            }
            .into(),
        ),
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
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
    assert!(changes[0].render().contains("remote_asn"));
    assert!(changes[1].render().contains("hold_time"));
    assert!(changes[2].render().contains("families"));
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
    assert!(changes[0].render().contains("<changed>"));
    assert!(!changes[0].render().contains("secret"));
}

#[test]
fn describe_neighbor_changes_hides_tcp_ao_key() {
    let old = test_neighbor("10.0.0.1", 65001);
    let mut new = old.clone();
    new.tcp_ao = Some(
        TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: true,
            deprecated: false,
        }
        .into(),
    );

    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].render(), "tcp_ao: <changed>  [restart required]");
    assert!(!changes[0].render().contains("secret"));
    assert_eq!(changes[0].old, serde_json::Value::Null);
    assert_eq!(changes[0].new, serde_json::Value::Null);
}

// ── LAN-321: operator-grade diff rendering + impact classification ───

#[test]
fn config_field_impact_surfaces_reload_matrix_classes() {
    use super::ConfigFieldImpact::{HotApplied, RestartRequired, SessionReset};
    let class = |field: &str| super::config_field_impact(field).map(|(class, _)| class);

    // Session-affecting: a hold_time edit classifies as session reset.
    assert_eq!(class("hold_time"), Some(SessionReset));
    assert_eq!(class("families"), Some(SessionReset));
    assert_eq!(class("md5_password"), Some(SessionReset));
    // Hot-applied: a description edit never touches the session.
    assert_eq!(class("description"), Some(HotApplied));
    assert_eq!(class("gr_peer_restart_time_max"), Some(HotApplied));
    assert_eq!(class("log_level"), Some(HotApplied));
    assert_eq!(class("max_prefixes"), Some(HotApplied));
    // Restart-required, matching the reload matrix pins.
    assert_eq!(class("tcp_ao"), Some(RestartRequired));
    assert_eq!(class("bfd"), Some(RestartRequired));
    // LAN-341 adjudication: both flow through the reconcile rebuild path
    // (remote_asn is not part of the diff key; a peer_group reassignment
    // changes the peer's effective inherited config), so both are honest
    // session resets in the diff annotations.
    assert_eq!(class("remote_asn"), Some(SessionReset));
    assert_eq!(class("peer_group"), Some(SessionReset));
}

// ── LAN-341: hot-applicable partition predicate ───────────────────────

#[test]
fn neighbor_change_hot_applicable_partitions_by_impact_class() {
    let old = test_neighbor("10.0.0.2", 65002);

    // Hot-applied-only edit → in-place apply.
    let mut hot = old.clone();
    hot.description = Some("edge".to_string());
    hot.gr_peer_restart_time_max = Some(300);
    hot.max_prefixes = Some(500);
    hot.import_policy_chain = vec!["allow-all".to_string()];
    assert!(super::neighbor_change_hot_applicable(&old, &hot));

    // No change at all → not hot-applicable (nothing to apply; the
    // caller's diff should not have flagged it).
    assert!(!super::neighbor_change_hot_applicable(&old, &old));

    // A session-reset field alone → rebuild.
    let mut reset = old.clone();
    reset.hold_time = Some(30);
    assert!(!super::neighbor_change_hot_applicable(&old, &reset));

    // Mixed hot + session-reset → rebuild (one bounce applies both).
    let mut mixed = hot.clone();
    mixed.hold_time = Some(30);
    assert!(!super::neighbor_change_hot_applicable(&old, &mixed));

    // remote_asn and peer_group edits are session resets, never hot.
    let mut asn = old.clone();
    asn.remote_asn = 65003;
    assert!(!super::neighbor_change_hot_applicable(&old, &asn));
    let mut group = old.clone();
    group.peer_group = Some("ix".to_string());
    assert!(!super::neighbor_change_hot_applicable(&old, &group));
}

#[test]
fn config_diff_human_output_is_operator_grade() {
    // Mixed diff: one added, one changed (hot + session-reset fields),
    // one untouched neighbor.
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors = vec![
        test_neighbor("10.0.0.2", 65002),
        test_neighbor("10.0.0.9", 65009),
    ];
    old.neighbors[0].hold_time = Some(90);
    let mut new = old.clone();
    new.neighbors[0].hold_time = Some(30);
    new.neighbors[0].description = Some("edge".to_string());
    new.neighbors.push(test_neighbor("10.0.0.3", 65003));

    let diff = super::diff_config(&old, &new);
    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());

    // The 0.50.0 defect: Rust Debug formatting leaked into operator output.
    assert!(!text.contains("Some("), "{text}");
    assert!(!text.contains("None"), "{text}");

    assert!(text.contains("+ 10.0.0.3 (AS 65003)"), "{text}");
    assert!(
        text.contains("hold_time: 90 → 30  [session reset: OPEN renegotiation]"),
        "{text}"
    );
    assert!(
        text.contains("description: (unset) → edge  [hot-applied]"),
        "{text}"
    );
    assert!(
        !text.contains("10.0.0.9"),
        "unchanged neighbors must not appear: {text}"
    );
    assert!(
        text.ends_with("Plan: 1 to add, 1 to change · 1 session will reset\n"),
        "{text}"
    );
}

#[test]
fn config_diff_json_changes_have_stable_field_shape() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors = vec![test_neighbor("10.0.0.2", 65002)];
    old.neighbors[0].hold_time = Some(90);
    let mut new = old.clone();
    new.neighbors[0].hold_time = Some(30);
    new.neighbors[0].description = Some("edge".to_string());

    let diff = super::diff_config(&old, &new);
    let json = super::config_diff_json_value(&diff);

    let changes = &json["reload_applied"]["neighbors"]["changed"][0]["changes"];
    // describe order: description before hold_time.
    assert_eq!(changes[0]["field"], "description");
    assert_eq!(changes[0]["old"], serde_json::Value::Null);
    assert_eq!(changes[0]["new"], "edge");
    assert_eq!(changes[0]["impact"], "hot_applied");
    assert_eq!(changes[1]["field"], "hold_time");
    assert_eq!(changes[1]["old"], 90);
    assert_eq!(changes[1]["new"], 30);
    assert_eq!(changes[1]["impact"], "session_reset");

    assert_eq!(json["summary"]["neighbors_added"], 0);
    assert_eq!(json["summary"]["neighbors_changed"], 1);
    assert_eq!(json["summary"]["neighbors_removed"], 0);
    assert_eq!(json["summary"]["sessions_will_reset"], 1);
    assert_eq!(json["summary"]["restart_required"], false);
}

#[test]
fn config_diff_summary_line_covers_restart_and_no_reset_cases() {
    // Hot-applied-only change: no session resets expected.
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors = vec![test_neighbor("10.0.0.2", 65002)];
    let mut new = old.clone();
    new.neighbors[0].description = Some("edge".to_string());
    let diff = super::diff_config(&old, &new);
    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(
        text.ends_with("Plan: 1 to change · no session resets expected\n"),
        "{text}"
    );

    // Restart-required change ([policy.explain]): the summary names the
    // restart and makes no "no resets" claim.
    let mut new = old.clone();
    new.policy.explain.cache_size = 512;
    let diff = super::diff_config(&old, &new);
    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(
        text.ends_with("Plan: no neighbor changes · daemon restart required for some changes\n"),
        "{text}"
    );
    assert!(!text.contains("no session resets expected"), "{text}");
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
            .any(|c| c.render().contains("hold_time"))
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
fn warm_cache_checkpoint_toggle_is_restart_required_and_defaults_off() {
    let old = parse(valid_toml()).unwrap();
    assert!(!old.global.warm_cache_checkpoint_on_shutdown);
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nwarm_cache_checkpoint_on_shutdown = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(new.global.warm_cache_checkpoint_on_shutdown);
    assert!(diff.global_changed);
    assert!(diff.has_restart_required_changes());
    assert!(!diff.has_reload_applied_changes());
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
                && summary
                    .changes
                    .iter()
                    .any(|change| change.render().contains("role"))
                && summary
                    .changes
                    .iter()
                    .any(|change| change.render().contains("strict_role"))),
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
        send_hold_time: None,
        ..Default::default()
    };
    let new = PeerGroupConfig {
        hold_time: Some(45),
        send_hold_time: None,
        ..Default::default()
    };
    let changes = super::describe_peer_group_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert!(changes[0].render().contains("hold_time"));
    assert!(changes[0].render().contains("90"));
    assert!(changes[0].render().contains("45"));
}

/// Policy-only edits are reload-applied (per-named definitions
/// flow through `apply_policy_change` on SIGHUP).
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

#[test]
fn dynamic_neighbor_tcp_ao_parses_directly_and_redacts_debug() {
    let config = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "dynamic-secret", send_id = 7, recv_id = 9, algorithm = "hmac(sha256)" }
"#,
    ))
    .unwrap();
    let tcp_ao = config.dynamic_neighbors[0].tcp_ao.as_ref().unwrap();
    let tcp_ao = &tcp_ao.0[0];
    assert_eq!(tcp_ao.send_id, 7);
    assert_eq!(tcp_ao.recv_id, 9);
    let rendered = format!("{tcp_ao:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("dynamic-secret"));
}

#[test]
fn dynamic_neighbor_tcp_ao_rejects_overlapping_dynamic_auth_boundaries() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }

[[dynamic_neighbors]]
prefix = "10.0.0.128/25"
peer_group = "ix-members"
"#,
    ))
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("TCP-AO and non-TCP-AO authentication boundary")
    );
}

#[test]
fn dynamic_neighbor_tcp_ao_rejects_static_peer_inside_prefix() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "2001:db8::/32"
peer_group = "ix-members"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "2001:db8::42"
remote_asn = 65002
"#,
    ))
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("TCP-AO and non-TCP-AO authentication boundary")
    );
}

#[test]
fn overlapping_tcp_ao_owners_require_directionally_disjoint_ids() {
    let allowed = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "covering", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[dynamic_neighbors]]
prefix = "10.0.0.128/25"
peer_group = "ix-members"
tcp_ao = { key = "specific", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    );
    parse(&allowed).expect("disjoint directional IDs permit overlapping AO owners");

    for (send_id, recv_id, expected) in [(1, 12, "SendID"), (2, 11, "RecvID")] {
        let candidate = allowed.replace(
            "send_id = 2, recv_id = 12",
            &format!("send_id = {send_id}, recv_id = {recv_id}"),
        );
        let err = parse(&candidate).unwrap_err().to_string();
        assert!(err.contains(expected), "{err}");
        assert!(err.contains("disjoint SendID and RecvID"), "{err}");
    }
}

#[test]
fn overlapping_static_exact_and_dynamic_tcp_ao_requires_disjoint_ids() {
    let source = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
tcp_ao = { key = "exact", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    );
    parse(&source).expect("static exact AO may overlap with disjoint IDs");

    let err = parse(&source.replace("send_id = 2", "send_id = 1"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("SendID"), "{err}");
}

#[test]
fn overlapping_ipv6_tcp_ao_owners_follow_the_same_directional_id_rules() {
    let source = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "2001:db8::/64"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "2001:db8::42"
remote_asn = 65002
tcp_ao = { key = "exact", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    );
    parse(&source).expect("IPv6 static and dynamic AO owners may overlap with disjoint IDs");

    let err = parse(&source.replace("recv_id = 12", "recv_id = 11"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("RecvID"), "{err}");
}

#[test]
fn tcp_ao_overlap_with_static_inherited_md5_fails_closed() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[peer_groups.legacy]
md5_password = "legacy"

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.42"
peer_group = "legacy"
remote_asn = 65002
"#,
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("TCP-AO and non-TCP-AO authentication boundary"),
        "{err}"
    );
}

#[test]
fn tcp_ao_overlap_with_static_md5_fails_closed() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
md5_password = "legacy"
"#,
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("TCP-AO and non-TCP-AO authentication boundary"),
        "{err}"
    );
}

#[test]
fn plaintext_dynamic_overlap_with_static_tcp_ao_fails_closed() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
tcp_ao = { key = "exact", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("TCP-AO and non-TCP-AO authentication boundary"),
        "{err}"
    );
}

#[test]
fn dynamic_neighbor_tcp_ao_rejects_peer_group_md5_inheritance() {
    let mut source = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#,
    );
    source = source.replace(
        "hold_time = 90",
        "hold_time = 90\nmd5_password = \"legacy\"",
    );
    let err = parse(&source).unwrap_err();
    assert!(err.to_string().contains("never inherited"));
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
bridge_vlan = 20
advertise_svi_mac = true
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.sorted()[0];
    assert_eq!(inst.id.as_u32(), 200);
    assert_eq!(inst.bridge.as_deref(), Some("br200"));
    assert_eq!(inst.bridge_vlan.unwrap().as_u32(), 20);
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
fn evpn_instance_bridge_vlan_accepts_bounds() {
    for vlan in [1, 4094] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = {vlan}
rd = "10.0.0.100:{vlan}"
route_targets = ["65000:{vlan}"]
local_vtep_ip = "10.0.0.100"
bridge = "br{vlan}"
bridge_vlan = {vlan}
"#
        ));
        let config = parse(&toml).unwrap();
        let table = config.resolve_evpn_instances().unwrap();
        let inst = table.get(EvpnInstanceId::new(vlan).unwrap()).unwrap();
        let bridge = format!("br{vlan}");
        assert_eq!(inst.bridge.as_deref(), Some(bridge.as_str()));
        assert_eq!(inst.bridge_vlan.unwrap().as_u32(), vlan);
    }
}

#[test]
fn evpn_instance_bridge_vlan_requires_bridge() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge_vlan = 10
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(
        err.to_string().contains("bridge_vlan requires bridge"),
        "got {err}"
    );
}

#[test]
fn evpn_instance_bridge_vlan_rejects_out_of_range() {
    for bad in [0, 4095, 70_000] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = {bad}
"#
        ));
        let err = parse(&toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidEvpnInstance { .. }),
            "expected InvalidEvpnInstance for bridge_vlan={bad}, got {err}"
        );
        assert!(
            err.to_string().contains("bridge_vlan must be in 1..=4094"),
            "unexpected message for bridge_vlan={bad}: {err}"
        );
    }
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
fn evpn_instance_bridge_vlan_redefine_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
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
bridge = "br100"
bridge_vlan = 10
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
}

#[test]
fn evpn_instance_swap_with_es_member_delete_decomposes_reload_applied() {
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
    // #268: the ES-member delete decomposes into an atomic-teardown step
    // (L2VNI 100 + its ES) followed by the L2VNI 300 add step.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 2 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn evpn_instance_add_existing_es_member_expansion_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
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
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
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
member_vnis = [100, 200]
originator_ip = "10.0.0.100"
"#,
    ))
    .unwrap();

    let diff = diff_config(&old, &new);
    assert!(diff.evpn_instances_changed);
    assert!(diff.ethernet_segments_changed);
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
fn evpn_instance_add_existing_es_field_change_decomposes_reload_applied() {
    let old = parse(&evpn_toml_with(
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
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
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
member_vnis = [100, 200]
originator_ip = "10.0.0.101"
"#,
    ))
    .unwrap();

    let diff = diff_config(&old, &new);
    assert!(diff.evpn_instances_changed);
    assert!(diff.ethernet_segments_changed);
    // #268: the ES field change + add-only build-up decomposes into an ES
    // redefine step followed by the add step, each its own generation.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 2 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
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
fn evpn_instance_mixed_redefine_swap_with_ip_vrf_link_marks_reload_applied() {
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
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
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
fn evpn_instance_multi_redefine_marks_reload_applied() {
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
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:222"
route_targets = ["65000:222"]
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
fn evpn_instance_multi_redefine_relink_decomposes_reload_applied() {
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
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:222"
route_targets = ["65000:222"]
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
    // #268: decomposes into a batch L2VNI redefine step and a pure relink step.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 2 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(
        json["evpn_runtime_change_class"]["reload_applied_decomposed"]["steps"],
        2
    );
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_mixed_redefine_relink_decomposes_reload_applied() {
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
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.100"

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
    // #268: decomposes into deletes, L2VNI redefine, relink, and add steps.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 4 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(
        json["evpn_runtime_change_class"]["reload_applied_decomposed"]["steps"],
        4
    );
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
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &comms,
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
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
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &comms,
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
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
    // `docs/soaks/soak-gate8b-mac-churn-24h.md`) and the M37
    // local-origination 24h soak (2026-05-19, postmortem
    // `docs/soaks/soak-m37-local-origination-churn-24h.md`) both passed
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
fn transaction_v1_required_family_edit_reshapes_dynamic_range() {
    // Load-bearing: reverting the config field makes the candidate fail to
    // parse; removing changed-group attribution for dynamic ranges leaves no
    // exact SessionReshape impact for this prefix.
    let config = |required: &str| {
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
families = ["ipv4_unicast", "ipv6_unicast"]
required_families = [{required}]
[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config("")).unwrap();
    let new = parse(&config("\"ipv6_unicast\"")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        diff.effective_neighbor_impact
            .iter()
            .map(|impact| (&impact.address, impact.kind, impact.is_dynamic_range))
            .collect::<Vec<_>>(),
        vec![(
            &"10.30.0.0/16".to_string(),
            EffectiveNeighborImpactKind::SessionReshape,
            true,
        )]
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

#[test]
fn transaction_v1_rejects_dynamic_tcp_ao_add_remove_rotate_and_move() {
    let absent = dynamic_tcp_ao_transaction_config(None, "");
    let original = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "old-secret")), "");
    let rotated = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "new-secret")), "");
    let moved = dynamic_tcp_ao_transaction_config(Some(("192.0.3.0/24", "old-secret")), "");

    for (label, old, new) in [
        ("add", &absent, &original),
        ("remove", &original, &absent),
        ("rotate", &original, &rotated),
        ("move", &original, &moved),
    ] {
        let diff = diff_config(old, new);
        let class = classify_config_transaction_v1(&diff);
        assert!(diff.dynamic_neighbor_tcp_ao_changed, "{label}");
        assert!(!diff.has_reload_applied_changes(), "{label}");
        assert!(!class.is_committable(), "{label}");
        assert!(class.supported_sections.is_empty(), "{label}: {class:?}");
        assert_eq!(
            class.restart_required_sections,
            vec!["[[dynamic_neighbors]].tcp_ao"],
            "{label}"
        );
        let json = config_diff_json_value(&diff);
        assert_eq!(json["reload_applied"]["dynamic_neighbors_changed"], false);
        assert_eq!(
            json["restart_required"]["dynamic_neighbor_tcp_ao_changed"],
            true
        );
    }
}

#[test]
fn transaction_v1_allows_disjoint_unprotected_dynamic_edit_beside_tcp_ao_range() {
    let old = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "secret")), "");
    let new = dynamic_tcp_ao_transaction_config(
        Some(("192.0.2.0/24", "secret")),
        "[[dynamic_neighbors]]\nprefix = \"198.51.100.0/24\"\npeer_group = \"dynamic\"\n",
    );
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.has_reload_applied_changes());
    assert!(class.is_committable(), "{class:?}");
    assert_eq!(class.supported_sections, vec!["[[dynamic_neighbors]]"]);
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn protected_dynamic_range_reorder_is_not_a_tcp_ao_restart_change() {
    let first = dynamic_tcp_ao_transaction_config(
        Some(("192.0.2.0/24", "first-secret")),
        "[[dynamic_neighbors]]\nprefix = \"198.51.100.0/24\"\npeer_group = \"dynamic\"\ntcp_ao = { key = \"second-secret\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }\n",
    );
    let second = dynamic_tcp_ao_transaction_config(
        Some(("198.51.100.0/24", "second-secret")),
        "[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"dynamic\"\ntcp_ao = { key = \"first-secret\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }\n",
    );

    let diff = diff_config(&first, &second);
    let class = classify_config_transaction_v1(&diff);
    assert!(!diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.dynamic_neighbors_reload_applied_changed);
    assert!(class.is_committable(), "{class:?}");
    assert_eq!(class.supported_sections, vec!["[[dynamic_neighbors]]"]);
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn protected_dynamic_range_effective_prefix_identity_avoids_restart_change() {
    let canonical = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "secret")), "");
    let host_bits = dynamic_tcp_ao_transaction_config(Some(("192.0.2.1/24", "secret")), "");

    let diff = diff_config(&canonical, &host_bits);
    assert!(!diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.dynamic_neighbors_reload_applied_changed);
}

#[test]
fn mixed_dynamic_tcp_ao_and_disjoint_unprotected_diff_reports_both_portions() {
    let old = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "old-secret")), "");
    let new = dynamic_tcp_ao_transaction_config(
        Some(("192.0.2.0/24", "new-secret")),
        "[[dynamic_neighbors]]\nprefix = \"198.51.100.0/24\"\npeer_group = \"dynamic\"\n",
    );
    let diff = diff_config(&old, &new);
    let json = config_diff_json_value(&diff);
    let text = format_config_diff(&diff);

    assert!(diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.dynamic_neighbors_reload_applied_changed);
    assert!(diff.has_restart_required_changes());
    assert!(diff.has_reload_applied_changes());
    assert_eq!(
        json["restart_required"]["dynamic_neighbor_tcp_ao_changed"],
        true
    );
    assert_eq!(json["reload_applied"]["dynamic_neighbors_changed"], true);
    assert!(
        text.contains("[[dynamic_neighbors]] matcher rebuilt"),
        "{text}"
    );
    assert!(
        text.contains("[[dynamic_neighbors]].tcp_ao changed"),
        "{text}"
    );

    let class = classify_config_transaction_v1(&diff);
    assert!(!class.is_committable());
    assert!(class.supported_sections.is_empty(), "{class:?}");
    assert_eq!(
        class.restart_required_sections,
        vec!["[[dynamic_neighbors]].tcp_ao"]
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
fn runtime_snapshot_token_does_not_encode_config_length() {
    // The normalized rendering includes plaintext secrets, so its byte
    // length must not appear in the token: configs whose secrets differ
    // only in length yield same-shape, digest-only tokens.
    let mut short = parse(valid_toml()).unwrap();
    short.neighbors[0].md5_password = Some("s".to_string());
    let mut long = short.clone();
    long.neighbors[0].md5_password = Some("s".repeat(64));

    let key = RuntimeSnapshotKey::random();
    let token_short = key.token(&short).unwrap();
    let token_long = key.token(&long).unwrap();
    assert_eq!(token_short.len(), "kv1:".len() + 16, "{token_short}");
    assert_eq!(token_short.len(), token_long.len());
    assert_ne!(token_short, token_long);
}

#[test]
fn neighbor_and_peer_group_debug_redact_md5_password() {
    let mut config = parse(valid_toml()).unwrap();
    config.neighbors[0].md5_password = Some("hunter2-secret".to_string());
    let rendered = format!("{:?}", config.neighbors[0]);
    assert!(!rendered.contains("hunter2-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let group = PeerGroupConfig {
        md5_password: Some("hunter2-secret".to_string()),
        ..PeerGroupConfig::default()
    };
    let rendered = format!("{group:?}");
    assert!(!rendered.contains("hunter2-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
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
fn evpn_ip_vrf_esi_mode_with_single_linked_segment_member_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

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
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    let vrf = table.get("tenant-blue").unwrap();
    assert_eq!(vrf.overlay_index_mode, rustbgpd_evpn::OverlayIndexMode::Esi);
    assert_eq!(
        vrf.overlay_index_esi.unwrap().octets(),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(
        vrf.overlay_index_mac.unwrap().octets(),
        [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
    );
    assert_eq!(vrf.overlay_index_l2vni, None);
}

#[test]
fn evpn_ip_vrf_esi_mode_requires_payload_fields() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

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
overlay_index_mode = "esi"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("overlay_index_esi"),
        "expected missing ESI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_fields_are_only_valid_in_esi_mode() {
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
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("only valid when overlay_index_mode = \"esi\""),
        "expected mode-gated field rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_mode_rejects_unknown_esi() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [100]
originator_ip = "10.0.0.100"

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
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("does not match any configured") && msg.contains("ethernet_segments"),
        "expected unknown ESI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_mode_requires_l2vni_when_multiple_linked() {
    let toml = evpn_toml_with(
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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100, 200]
originator_ip = "10.0.0.100"

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
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("multiple linked L2VNIs") && msg.contains("overlay_index_l2vni"),
        "expected ambiguous linked-L2VNI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_mode_rejects_l2vni_outside_segment() {
    let toml = evpn_toml_with(
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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.100"

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
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
overlay_index_l2vni = 200
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not a member of overlay_index_esi"),
        "expected selected-L2VNI segment-membership rejection, got {msg}"
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
    "slow_peer_threshold_pct",
    "slow_peer_duration",
    "slow_peer_isolation",
    "max_prefixes",
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
    "slow_peer_threshold_pct",
    "slow_peer_duration",
    "slow_peer_isolation",
    "max_prefixes",
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

#[test]
fn reload_matrix_documents_every_neighbor_field() {
    let matrix = load_reload_matrix();
    let section = reload_matrix_section(&matrix, "## `[[neighbors]]`", "## `[peer_groups.<name>]`");
    for field in RELOAD_MATRIX_NEIGHBOR_FIELDS {
        let needle = format!("`{field}`");
        assert!(
            section.contains(&needle),
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
    let section = reload_matrix_section(
        &matrix,
        "## `[peer_groups.<name>]`",
        "## `[[dynamic_neighbors]]`",
    );
    for field in RELOAD_MATRIX_PEER_GROUP_FIELDS {
        let needle = format!("`{field}`");
        assert!(
            section.contains(&needle),
            "PeerGroupConfig field {needle} is in \
             RELOAD_MATRIX_PEER_GROUP_FIELDS (src/config/tests.rs) but \
             absent from docs/reload-matrix.md. Either add a row for it \
             in the [[peer_groups]] section of the matrix, or remove the \
             entry from the list."
        );
    }
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

/// The name-coverage tests above only prove a field *appears* in the
/// matrix. This one pins the CLASS column (live vs restart-required) for
/// the knobs where the class is load-bearing — a docs-vs-reality drift on
/// these actively misleads an operator about whether a SIGHUP suffices.
///
/// `log_level` is now genuinely live (re-applied on SIGHUP via the
/// telemetry tracing reload handle), so the doc claim is finally true; if
/// someone regresses it back to inert and re-marks the row restart-required
/// (or vice versa) this fails. `tcp_ao` pins its deliberately narrow SIGHUP
/// exception: add-only install and later observation-gated selection are live,
/// while destructive/identity edits remain restart-required. `bfd` pins the unconditional
/// restart-required side so a blanket "mark everything live" edit also fails.
#[test]
fn reload_matrix_pins_load_bearing_field_classes() {
    let matrix = load_reload_matrix();
    for (field, class_cell) in [
        ("log_level", "| live |"),
        (
            "tcp_ao",
            "| live (non-destructive generations) / otherwise restart-required |",
        ),
        ("bfd", "| restart-required |"),
    ] {
        let rows = reload_matrix_rows_for(&matrix, field);
        assert!(
            !rows.is_empty(),
            "no reload-matrix table row found for `{field}`"
        );
        for row in rows {
            assert!(
                row.contains(class_cell),
                "reload-matrix class drift: the row for `{field}` must be \
                 classed `{class_cell}` (load-bearing: it tells operators \
                 whether SIGHUP is enough). Row reads: {row}"
            );
        }
    }

    let cap_rows = reload_matrix_rows_for(&matrix, "gr_peer_restart_time_max");
    assert_eq!(
        cap_rows.len(),
        2,
        "the GR peer restart cap must have neighbor and peer-group rows"
    );
    assert!(
        cap_rows[0].contains("| live |"),
        "the neighbor cap is hot-applied in place: {}",
        cap_rows[0]
    );
    assert!(
        cap_rows[1].contains("| live (static session reset; dynamic next reconnect) |"),
        "peer-group cap edits do not selectively hot-fanout: {}",
        cap_rows[1]
    );
}

#[test]
fn config_knob_contributor_guide_pins_required_review_surfaces() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/config-knob-contributor-guide.md");
    let guide = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "could not read {} for config-knob guide structural test: {err}",
            path.display()
        )
    });
    for required in [
        "src/config/schema.rs",
        "src/config/validation.rs",
        "docs/reload-matrix.md",
        "RELOAD_MATRIX_NEIGHBOR_FIELDS",
        "RELOAD_MATRIX_PEER_GROUP_FIELDS",
        "docs/CONFIGURATION.md",
        "persist",
    ] {
        assert!(
            guide.contains(required),
            "config knob contributor guide must mention {required:?}"
        );
    }
}

/// Regression guard for the directive format itself: every string
/// `per_peer_log_directives` emits must actually parse as an `EnvFilter`
/// directive. The original `peer{peer_addr=X}=level` form (no brackets)
/// did NOT parse — `init_logging` rejected it and aborted daemon boot the
/// moment any neighbor set a `log_level`, so the per-peer knob was inert
/// *and* boot-fatal. The bracketed `[peer{peer_addr=X}]=level` form parses;
/// this pins it so the format can't silently regress into a boot-abort.
#[test]
fn per_peer_log_directives_parse_as_env_filter() {
    use tracing_subscriber::filter::Directive;

    // Appends `log_level` onto the fixture's single 10.0.0.2 neighbor.
    let config = parse(&format!("{}log_level = \"debug\"\n", valid_toml())).unwrap();
    let directives = config.per_peer_log_directives();
    assert_eq!(directives.len(), 1, "one neighbor carries a log_level");
    assert!(
        directives[0].starts_with("[peer{"),
        "span directive must be bracketed, got {:?}",
        directives[0]
    );
    for directive in &directives {
        directive.parse::<Directive>().unwrap_or_else(|e| {
            panic!(
                "per_peer_log_directives emitted {directive:?} which EnvFilter \
                 rejects ({e}) — init_logging would abort daemon boot"
            )
        });
    }
}

#[test]
fn managed_netdevs_default_empty_and_resolve_stamps() {
    let config = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = true\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan200\"\nvni = 200\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vlan_uppers]]\nname = \"br100.10\"\nbridge = \"br100\"\nvlan = 10\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ))
    .unwrap();

    let table = config.resolve_managed_netdevs().unwrap();
    assert_eq!(table.owner_token(), Some("leaf-1"));
    let bridge = table.bridge("br100").unwrap();
    assert_eq!(bridge.name, "br100");
    assert!(bridge.vlan_filtering);
    assert_eq!(bridge.ownership_stamp, "rustbgpd:bridge:leaf-1:br100");
    let vxlan = table.vxlan("vxlan200").unwrap();
    assert_eq!(vxlan.name, "vxlan200");
    assert_eq!(vxlan.spec.vni, 200);
    assert_eq!(
        vxlan.spec.local_ip,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(vxlan.spec.dstport, 4789);
    assert_eq!(vxlan.spec.bridge, "br100");
    assert_eq!(vxlan.ownership_stamp, "rustbgpd:vxlan:leaf-1:vxlan200");
    let svd_vxlan = table.svd_vxlan("vxlan-svd").unwrap();
    assert_eq!(svd_vxlan.name, "vxlan-svd");
    assert_eq!(
        svd_vxlan.spec.local_ip,
        Some("10.0.0.1".parse::<std::net::IpAddr>().unwrap())
    );
    assert_eq!(svd_vxlan.spec.dstport, 4789);
    assert_eq!(svd_vxlan.spec.bridge, "br100");
    assert_eq!(svd_vxlan.spec.bindings.len(), 1);
    assert_eq!(svd_vxlan.spec.bindings[0].bridge_vlan, 10);
    assert_eq!(svd_vxlan.spec.bindings[0].vni, 100);
    assert_eq!(
        svd_vxlan.ownership_stamp,
        "rustbgpd:svd-vxlan:leaf-1:vxlan-svd"
    );
    let vlan_upper = table.vlan_upper("br100.10").unwrap();
    assert_eq!(vlan_upper.name, "br100.10");
    assert_eq!(vlan_upper.spec.bridge, "br100");
    assert_eq!(vlan_upper.spec.vlan, 10);
    assert_eq!(
        vlan_upper.ownership_stamp,
        "rustbgpd:vlan-upper:leaf-1:br100.10"
    );
    let vrf = table.vrf("vrf100").unwrap();
    assert_eq!(vrf.name, "vrf100");
    assert_eq!(vrf.spec.table_id, 5000);
    assert_eq!(vrf.ownership_stamp, "rustbgpd:vrf:leaf-1:vrf100");
    let l3vxlan = table.l3vxlan("l3vxlan100").unwrap();
    assert_eq!(l3vxlan.name, "l3vxlan100");
    assert_eq!(l3vxlan.spec.vni, 5000);
    assert_eq!(
        l3vxlan.spec.local_ip,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(l3vxlan.spec.dstport, 4789);
    assert_eq!(l3vxlan.spec.vrf, "vrf100");
    assert_eq!(
        l3vxlan.spec.router_mac,
        rustbgpd_wire::MacAddress::new([0x02, 0, 0, 0, 0, 1])
    );
    assert_eq!(
        l3vxlan.ownership_stamp,
        "rustbgpd:l3vxlan:leaf-1:l3vxlan100"
    );

    let owner_only = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n",
        valid_toml()
    ))
    .unwrap();
    let owner_only_table = owner_only.resolve_managed_netdevs().unwrap();
    assert_eq!(owner_only_table.owner_token(), Some("leaf-1"));
    assert!(
        !owner_only_table.is_empty(),
        "owner-only managed_netdevs config must still spawn the dataplane actor for cleanup"
    );

    let empty = parse(valid_toml()).unwrap();
    assert!(empty.resolve_managed_netdevs().unwrap().is_empty());
}

#[test]
fn managed_netdevs_reject_missing_owner_duplicate_and_invalid_names() {
    let missing_owner = parse(&format!(
        "{}\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        missing_owner,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let duplicate = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = false\n\n[[managed_netdevs.vxlans]]\nname = \"br100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        duplicate,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let invalid_owner = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf 1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = false\n",
        valid_toml()
    ));
    assert!(matches!(
        invalid_owner,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let invalid_name = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan 100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    match invalid_name {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must contain only ASCII"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid VXLAN name rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_unknown_fields() {
    let unknown_top_level = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\nunknown = true\n",
        valid_toml()
    ));
    assert!(matches!(unknown_top_level, Err(ConfigError::Parse(_))));

    let unknown_bridge_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = true\nmtu = 9000\n",
        valid_toml()
    ));
    assert!(matches!(unknown_bridge_field, Err(ConfigError::Parse(_))));

    let unknown_vxlan_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\nexternal = true\n",
        valid_toml()
    ));
    assert!(matches!(unknown_vxlan_field, Err(ConfigError::Parse(_))));

    let unknown_vrf_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\nmtu = 9000\n",
        valid_toml()
    ));
    assert!(matches!(unknown_vrf_field, Err(ConfigError::Parse(_))));

    let unknown_l3vxlan_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\nexternal = true\n",
        valid_toml()
    ));
    assert!(matches!(unknown_l3vxlan_field, Err(ConfigError::Parse(_))));

    let unknown_vlan_upper_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vlan_uppers]]\nname = \"br100.10\"\nbridge = \"br100\"\nvlan = 10\nprotocol = \"802.1ad\"\n",
        valid_toml()
    ));
    assert!(matches!(
        unknown_vlan_upper_field,
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn managed_netdevs_reject_invalid_vlan_upper_fields() {
    let candidate = |body: &str| parse(&format!("{}\n{body}", valid_toml()));

    let missing_instance = candidate(
        r#"[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.10"
bridge = "br100"
vlan = 10
"#,
    );
    match missing_instance {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("bridge_vlan"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected missing bridge_vlan binding rejection, got {other:?}"),
    }

    let duplicate_binding = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.10"
bridge = "br100"
vlan = 10

[[managed_netdevs.vlan_uppers]]
name = "br100.10b"
bridge = "br100"
vlan = 10
"#,
    );
    match duplicate_binding {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("duplicate"), "unexpected reason: {reason}");
        }
        other => panic!("expected duplicate VLAN upper binding rejection, got {other:?}"),
    }

    let zero_vlan = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.0"
bridge = "br100"
vlan = 0
"#,
    );
    assert!(matches!(
        zero_vlan,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));
}

#[test]
fn managed_netdevs_reject_invalid_vlan_upper_bindings_and_names() {
    let candidate = |body: &str| parse(&format!("{}\n{body}", valid_toml()));

    // vlan above the Linux upper bound: the range check fires before the
    // binding check, so no matching [[evpn_instances]] is needed.
    let vlan_too_high = candidate(
        r#"[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.95"
bridge = "br100"
vlan = 4095
"#,
    );
    match vlan_too_high {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("1..=4094"), "unexpected reason: {reason}");
        }
        other => panic!("expected out-of-range VLAN upper rejection, got {other:?}"),
    }

    // An in-range vlan whose (bridge, vlan) pair does not match any configured
    // EVI binding is rejected: a *wrong* binding, not merely a missing one.
    let mismatched_binding = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.20"
bridge = "br100"
vlan = 20
"#,
    );
    match mismatched_binding {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must match a configured [[evpn_instances]]"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected mismatched EVI binding rejection, got {other:?}"),
    }

    // Names dedup across all managed-netdev classes: a bridge and a VLAN upper
    // sharing a name collide. Bridges validate before VLAN uppers, so the
    // collision is detected on the VLAN upper insert.
    let cross_class_duplicate_name = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.bridges]]
name = "shared0"
vlan_filtering = true

[[managed_netdevs.vlan_uppers]]
name = "shared0"
bridge = "br100"
vlan = 10
"#,
    );
    match cross_class_duplicate_name {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("duplicate"), "unexpected reason: {reason}");
        }
        other => panic!("expected cross-class duplicate name rejection, got {other:?}"),
    }

    // An invalid link name (a space is not an allowed ifname character) is
    // rejected by validate_managed_link_name.
    let invalid_name = candidate(
        r#"[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100 10"
bridge = "br100"
vlan = 10
"#,
    );
    match invalid_name {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must contain only ASCII"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid VLAN-upper name rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_invalid_vxlan_fields() {
    let invalid_vni = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 16777216\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        invalid_vni,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let invalid_dstport = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\ndstport = 0\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        invalid_dstport,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let learning_enabled = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\nlearning = true\n",
        valid_toml()
    ));
    assert!(matches!(
        learning_enabled,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));
}

#[test]
fn managed_netdevs_reject_duplicate_vxlan_vni() {
    let duplicate_vni = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan200\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br200\"\n",
        valid_toml()
    ));
    match duplicate_vni {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("duplicate vni"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected duplicate-vni rejection, got {other:?}"),
    }

    // Distinct VNIs on distinct names load cleanly.
    let distinct_vnis = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan200\"\nvni = 200\nlocal = \"10.0.0.1\"\nbridge = \"br200\"\n",
        valid_toml()
    ));
    assert!(distinct_vnis.is_ok(), "got {distinct_vnis:?}");
}

#[test]
fn managed_netdevs_reject_fixed_vxlan_vni_colliding_with_svd_binding() {
    let collision = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    match collision {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("fixed-VNI") && reason.contains("SVD"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected fixed-vxlan/svd VNI collision rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_svd_binding_same_vlan_conflicting_vnis() {
    let conflict = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[[evpn_instances]]\nvni = 200\nrd = \"10.0.0.100:200\"\nroute_targets = [\"65000:200\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    match conflict {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("conflicting"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected SVD bridge_vlan VNI conflict rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_accept_svd_binding_distinct_vlans() {
    let config = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[[evpn_instances]]\nvni = 200\nrd = \"10.0.0.100:200\"\nroute_targets = [\"65000:200\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 20\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ))
    .unwrap();
    let table = config.resolve_managed_netdevs().unwrap();
    let svd_vxlan = table.svd_vxlan("vxlan-svd").unwrap();
    assert_eq!(svd_vxlan.spec.bindings.len(), 2);
    let mapped: std::collections::BTreeMap<u16, u32> = svd_vxlan
        .spec
        .bindings
        .iter()
        .map(|b| (b.bridge_vlan, b.vni))
        .collect();
    assert_eq!(mapped.get(&10), Some(&100));
    assert_eq!(mapped.get(&20), Some(&200));
}

#[test]
fn managed_netdevs_reject_invalid_vrf_and_l3vxlan_fields() {
    let zero_table = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 0\n",
        valid_toml()
    ));
    assert!(matches!(
        zero_table,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let duplicate_table = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n\n[[managed_netdevs.vrfs]]\nname = \"vrf200\"\ntable_id = 5000\n",
        valid_toml()
    ));
    assert!(matches!(
        duplicate_table,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let duplicate_l3_vni = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan200\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf200\"\nrouter_mac = \"02:00:00:00:00:02\"\n",
        valid_toml()
    ));
    assert!(matches!(
        duplicate_l3_vni,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let learning_enabled = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\nlearning = true\n",
        valid_toml()
    ));
    assert!(matches!(
        learning_enabled,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let multicast_router_mac = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"01:00:5e:00:00:01\"\n",
        valid_toml()
    ));
    assert!(matches!(
        multicast_router_mac,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));
}

#[test]
fn managed_netdevs_reject_reserved_vrf_table_id() {
    for id in [252, 253, 254, 255] {
        let reserved = parse(&format!(
            "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = {id}\n",
            valid_toml()
        ));
        match reserved {
            Err(ConfigError::InvalidManagedNetdev { reason }) => {
                assert!(
                    reason.contains("reserved"),
                    "unexpected reason for table_id {id}: {reason}"
                );
            }
            other => panic!("expected reserved-table rejection for {id}, got {other:?}"),
        }
    }

    // A non-reserved table_id still loads.
    let ok = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n",
        valid_toml()
    ));
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_vrf_table_id_colliding_with_fib_table() {
    let collision = parse(&format!(
        "{}\n[[fib_tables]]\nname = \"edge\"\ntable_id = 5000\nmetric = 200\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n",
        valid_toml()
    ));
    match collision {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("fib_tables"), "unexpected reason: {reason}");
        }
        other => panic!("expected vrf/fib_tables collision rejection, got {other:?}"),
    }

    // Distinct table_ids load cleanly.
    let ok = parse(&format!(
        "{}\n[[fib_tables]]\nname = \"edge\"\ntable_id = 1000\nmetric = 200\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n",
        valid_toml()
    ));
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_l3vxlan_vni_colliding_with_vxlan_vni() {
    let collision = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 6000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ));
    match collision {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("L3VNI") && reason.contains("L2VNI"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected l3vxlan/vxlan VNI collision rejection, got {other:?}"),
    }

    // Distinct L2/L3 VNIs load cleanly.
    let ok = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 6000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ));
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_l3vxlan_without_managed_vrf_reference() {
    let missing_vrf = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ));
    match missing_vrf {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must reference a configured [[managed_netdevs.vrfs]] row"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected missing managed VRF reference rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_ip_vrf_managed_identity_mismatch() {
    let candidate = |vrf_table_id: u32, l3vni: u32, l3_local: &str, router_mac: &str| {
        parse(&format!(
            r#"{}
[[evpn_ip_vrfs]]
name = "blue"
vni = 5000
rd = "10.0.0.1:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf100"
l3vxlan_device = "l3vxlan5000"
table_id = 5000

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vrfs]]
name = "vrf100"
table_id = {vrf_table_id}

[[managed_netdevs.l3vxlans]]
name = "l3vxlan5000"
vni = {l3vni}
local = "{l3_local}"
vrf = "vrf100"
router_mac = "{router_mac}"
"#,
            valid_toml()
        ))
    };

    for (case, result, expected) in [
        (
            "vrf table",
            candidate(5001, 5000, "10.0.0.1", "02:00:00:00:00:01"),
            "table_id",
        ),
        (
            "l3vni",
            candidate(5000, 5001, "10.0.0.1", "02:00:00:00:00:01"),
            "vni",
        ),
        (
            "local",
            candidate(5000, 5000, "10.0.0.2", "02:00:00:00:00:01"),
            "local",
        ),
        (
            "router_mac",
            candidate(5000, 5000, "10.0.0.1", "02:00:00:00:00:02"),
            "router_mac",
        ),
    ] {
        match result {
            Err(ConfigError::InvalidManagedNetdev { reason }) => {
                assert!(
                    reason.contains(expected),
                    "unexpected {case} reason: {reason}"
                );
            }
            other => panic!("expected {case} mismatch rejection, got {other:?}"),
        }
    }

    let ok = candidate(5000, 5000, "10.0.0.1", "02:00:00:00:00:01");
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_ip_vrf_l3vxlan_vrf_mismatch() {
    // Two managed VRFs; the IP-VRF expects `vrf-blue` but the managed
    // L3VXLAN it binds is enslaved to `vrf-green`. vni/local/router_mac
    // and the `vrf-blue` table_id all match the IP-VRF, so the only
    // remaining divergence is the VRF the L3VXLAN attaches to — without
    // this check the lifecycle enslaves to the wrong VRF and IP-VRF
    // readiness (master == vrf_device) can never reach Ready.
    let candidate = |l3vxlan_vrf: &str| {
        parse(&format!(
            r#"{}
[[evpn_ip_vrfs]]
name = "blue"
vni = 5000
rd = "10.0.0.1:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "l3vxlan5000"
table_id = 5000

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vrfs]]
name = "vrf-blue"
table_id = 5000

[[managed_netdevs.vrfs]]
name = "vrf-green"
table_id = 6000

[[managed_netdevs.l3vxlans]]
name = "l3vxlan5000"
vni = 5000
local = "10.0.0.1"
vrf = "{l3vxlan_vrf}"
router_mac = "02:00:00:00:00:01"
"#,
            valid_toml()
        ))
    };

    match candidate("vrf-green") {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("vrf") && reason.contains("vrf_device"),
                "unexpected vrf-mismatch reason: {reason}"
            );
        }
        other => panic!("expected L3VXLAN vrf/vrf_device mismatch rejection, got {other:?}"),
    }

    let ok = candidate("vrf-blue");
    assert!(ok.is_ok(), "matching L3VXLAN vrf should load, got {ok:?}");
}

#[test]
fn managed_netdevs_valid_multi_class_config_loads() {
    let config = parse(&format!(
        "{}\n[[fib_tables]]\nname = \"edge\"\ntable_id = 1000\nmetric = 200\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = true\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf-blue\"\ntable_id = 5000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan5000\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf-blue\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ))
    .expect("valid multi-class managed-netdev config should load");
    assert_eq!(config.managed_netdevs.bridges.len(), 1);
    assert_eq!(config.managed_netdevs.vxlans.len(), 1);
    assert_eq!(config.managed_netdevs.vrfs.len(), 1);
    assert_eq!(config.managed_netdevs.l3vxlans.len(), 1);
}

#[test]
fn managed_netdevs_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = false\n",
        valid_toml()
    ))
    .unwrap();

    let diff = diff_config(&old, &new);
    assert!(diff.managed_netdevs_changed);
    assert!(diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["managed_netdevs_changed"], true);
    let text = format_config_diff(&diff);
    assert!(text.contains("[managed_netdevs] changed"));
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

[security.grpc]
enforcement = "legacy"

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
    fs::write(dir.path().join("config.toml"), toml).expect("write config");
    dir
}

fn load_dir(dir: &tempfile::TempDir) -> Result<Config, String> {
    Config::load_with_diagnostics(dir.path().join("config.toml").to_str().unwrap())
}

#[test]
fn rpol_files_load_resolve_and_evaluate_in_chains() {
    let dir = rpol_config_dir(
        RPOL_SOURCE,
        r#""customer-in(200)", "bogon-filter", "toml-pass""#,
    );
    let config = load_dir(&dir).expect("config with rpol files loads");

    // Relative path rewritten absolute against the config dir.
    assert_eq!(config.policy.rpol_files.len(), 1);
    assert!(
        Path::new(&config.policy.rpol_files[0]).is_absolute(),
        "{:?}",
        config.policy.rpol_files[0]
    );
    assert_eq!(config.policy.rpol.policies.len(), 2);

    // Resolver equivalence: the neighbor's effective import chain
    // carries pre-compiled rpol members mixed with the TOML policy,
    // and routes flow / are denied per the policy through the same
    // chain-eval seam sessions use.
    let neighbor = &config.neighbors[0];
    let (import, _) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("chains resolve");
    let import = import.expect("import chain configured");
    assert_eq!(import.policies.len(), 3);
    assert_eq!(import.policies[0].name.as_deref(), Some("customer-in(200)"));
    assert!(import.policies[0].rpol.is_some());
    assert!(import.policies[2].rpol.is_none());

    let ctx = |prefix: Prefix| rustbgpd_policy::RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
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
    };
    let customer = Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        "10.10.3.0".parse().unwrap(),
        24,
    ));
    let bogon = Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        "127.0.0.0".parse().unwrap(),
        8,
    ));
    let (result, eval) =
        rustbgpd_policy::evaluate_chain_with_attribution(Some(&import), &ctx(customer));
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Permit);
    assert_eq!(result.modifications.set_local_pref, Some(200));
    assert_eq!(eval.matched_policy.as_deref(), Some("toml-pass"));
    let (result, eval) =
        rustbgpd_policy::evaluate_chain_with_attribution(Some(&import), &ctx(bogon));
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Deny);
    assert_eq!(eval.matched_policy.as_deref(), Some("bogon-filter"));
}

/// LAN-300: a config-referenced `.rpol` file resolves its `import`
/// graph — from its own directory and from `[policy] rpol_roots`
/// (rewritten absolute like `rpol_files`) — and a broken import
/// anywhere rejects the whole load (one atomic candidate per unit,
/// ADR-0103 Decision 8.1).
#[test]
fn rpol_imports_resolve_through_config_roots_and_fail_atomically() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::create_dir_all(dir.path().join("shared/lib")).expect("mkdir");
    fs::write(
        dir.path().join("shared/lib/bogons.rpol"),
        "prefix-set bogons { 127.0.0.0/8 le 32 }",
    )
    .expect("write lib");
    fs::write(
        dir.path().join("policies/core.rpol"),
        "import \"lib/bogons.rpol\"\n\
         policy edge-in { term bogon { if route.prefix in bogons { reject } } }",
    )
    .expect("write rpol");
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[policy]
rpol_files = ["policies/core.rpol"]
rpol_roots = ["shared"]
import_chain = ["edge-in"]
"#;
    fs::write(dir.path().join("config.toml"), toml).expect("write config");
    let config = load_dir(&dir).expect("config with rpol imports loads");
    // Roots rewritten absolute, like rpol_files.
    assert_eq!(config.policy.rpol_roots.len(), 1);
    assert!(Path::new(&config.policy.rpol_roots[0]).is_absolute());
    // The imported prefix-set participates in the compiled chain.
    let chain = config.import_chain().expect("resolves").expect("present");
    let ctx = rustbgpd_policy::RouteContext {
        prefix: Some(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            "127.0.0.1".parse().unwrap(),
            32,
        ))),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
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
    };
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Deny);

    // Break the imported leaf: the WHOLE config load is rejected —
    // no partial registry, and the diagnostic names the leaf file.
    fs::write(
        dir.path().join("shared/lib/bogons.rpol"),
        "prefix-set bogons { not-a-prefix }",
    )
    .expect("rewrite lib");
    let err = load_dir(&dir).expect_err("broken import rejects the load");
    assert!(err.contains("bogons.rpol"), "names the leaf module: {err}");
}

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

[security.grpc]
enforcement = "legacy"

[policy]
rpol_files = ["policies/core.rpol"]

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = [{import_chain}]
export_policy_chain = [{export_chain}]
"#,
    );
    fs::write(dir.path().join("config.toml"), toml).expect("write config");
    dir
}

const PREPEND_OPERANDS_RPOL: &str = r"
policy peer-pad { term inbound-pad { prepend as peer 3; accept } }
policy self-pad { term outbound-pad { prepend as self 3; accept } }
policy origin-pad { term origin-pad { prepend as origin 2; accept } }
";

/// Direction legality is enforced when the chain is attached: a
/// `prepend as peer` member is import-only, and binding it as an
/// export chain fails the config load with the exact diagnostic.
#[test]
fn prepend_as_peer_rejected_on_export_attachment() {
    let dir = rpol_directional_config_dir(PREPEND_OPERANDS_RPOL, r#""peer-pad""#, r#""peer-pad""#);
    let error = load_dir(&dir).expect_err("export-bound `prepend as peer` must fail the load");
    assert!(error.contains("peer-pad"), "{error}");
    assert!(error.contains("inbound-pad"), "{error}");
    assert!(error.contains("prepend as peer"), "{error}");
    assert!(error.contains("import-only"), "{error}");
    assert!(error.contains("own-AS loop"), "{error}");
}

/// The legal cells of the matrix: `peer` on import, `self`/`origin` on
/// export (and import). The export chain's rpol members carry the
/// attach-time `[global] asn`, so `prepend as self` resolves to it.
#[test]
fn prepend_operand_legal_directions_attach_and_resolve() {
    let dir = rpol_directional_config_dir(
        PREPEND_OPERANDS_RPOL,
        r#""peer-pad", "origin-pad""#,
        r#""self-pad", "origin-pad""#,
    );
    let config = load_dir(&dir).expect("legal operand placements load");
    let neighbor = &config.neighbors[0];
    let (import, export) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("chains resolve");
    let import = import.expect("import chain configured");
    let export = export.expect("export chain configured");

    // Attach-time local_asn stamp on every rpol member.
    for chain in [&import, &export] {
        for member in &chain.policies {
            let compiled = member.rpol.as_deref().expect("rpol member");
            assert_eq!(compiled.local_asn, Some(65001));
        }
    }

    let ctx = rustbgpd_policy::RouteContext {
        prefix: Some(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            "10.10.3.0".parse().unwrap(),
            24,
        ))),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 1,
        origin_asn: Some(64500),
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: Some(65002),
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    // Import: `prepend as peer` resolves to the neighbor's ASN (the
    // later `origin-pad` member wins the shared prepend slot — chain
    // merge semantics — so evaluate the peer-pad member's chain alone).
    let peer_only = rustbgpd_policy::PolicyChain::from_named(vec![import.policies[0].clone()]);
    let result = peer_only.evaluate(&ctx);
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Permit);
    assert_eq!(result.modifications.as_path_prepend, Some((65002, 3)));

    // Export: `prepend as self` resolves to the daemon's [global] asn.
    let self_only = rustbgpd_policy::PolicyChain::from_named(vec![export.policies[0].clone()]);
    let result = self_only.evaluate(&ctx);
    assert_eq!(result.modifications.as_path_prepend, Some((65001, 3)));

    // Both directions: `origin` resolves from the route.
    let result = export.evaluate(&ctx);
    assert_eq!(result.modifications.as_path_prepend, Some((64500, 2)));
}

/// `prepend as peer` on the GLOBAL export chain is rejected too — the
/// direction check lives in the shared resolver, not per-neighbor.
#[test]
fn prepend_as_peer_rejected_on_global_export_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), PREPEND_OPERANDS_RPOL).expect("write rpol");
    fs::write(
        dir.path().join("config.toml"),
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[policy]
rpol_files = ["policies/core.rpol"]
export_chain = ["peer-pad"]
"#,
    )
    .expect("write config");
    let error = load_dir(&dir).expect_err("global export `prepend as peer` must fail");
    assert!(error.contains("prepend as peer"), "{error}");
    assert!(error.contains("import-only"), "{error}");
}

#[test]
fn rpol_compile_diagnostics_fail_config_load() {
    let dir = rpol_config_dir(
        "policy broken { term t { if route.nosuch == 1 { reject } } }",
        r#""broken""#,
    );
    let error = load_dir(&dir).expect_err("bad rpol file must fail the load");
    assert!(error.contains("core.rpol"), "{error}");
    // The ariadne-rendered diagnostic is embedded in the error string.
    assert!(
        error.contains("route.nosuch") || error.contains("nosuch"),
        "{error}"
    );
}

#[test]
fn rpol_missing_file_fails_config_load() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""bogon-filter""#);
    fs::remove_file(dir.path().join("policies/core.rpol")).unwrap();
    let error = load_dir(&dir).expect_err("missing rpol file must fail the load");
    assert!(error.contains("failed to read"), "{error}");
}

/// LAN-218: entries are `canonicalize()`d before reading, so an
/// `rpol_files` path that points through a symlink still resolves to and
/// loads the real file's content.
#[cfg(unix)]
#[test]
fn rpol_symlinked_file_canonicalizes_and_loads() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""bogon-filter""#);
    std::os::unix::fs::symlink(
        dir.path().join("policies/core.rpol"),
        dir.path().join("policies/link.rpol"),
    )
    .unwrap();
    let toml_path = dir.path().join("config.toml");
    let toml = fs::read_to_string(&toml_path).unwrap().replace(
        r#"rpol_files = ["policies/core.rpol"]"#,
        r#"rpol_files = ["policies/link.rpol"]"#,
    );
    fs::write(&toml_path, toml).unwrap();

    let config = load_dir(&dir).expect("symlinked rpol file loads");
    // Content read through the symlink: both policies registered.
    assert_eq!(config.policy.rpol.policies.len(), 2);
    assert!(config.policy.rpol.policies.contains_key("bogon-filter"));
    assert!(config.policy.rpol.policies.contains_key("customer-in"));
}

#[test]
fn rpol_name_collision_with_toml_definition_fails() {
    let dir = rpol_config_dir("policy toml-pass { term t { reject } }", r#""toml-pass""#);
    let error = load_dir(&dir).expect_err("collision must fail the load");
    assert!(error.contains("toml-pass"), "{error}");
    assert!(error.contains("policy.definitions"), "{error}");
}

#[test]
fn rpol_name_collision_across_files_fails() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""bogon-filter""#);
    fs::write(
        dir.path().join("policies/dup.rpol"),
        "policy bogon-filter { term t { reject } }",
    )
    .unwrap();
    let toml_path = dir.path().join("config.toml");
    let toml = fs::read_to_string(&toml_path).unwrap().replace(
        r#"rpol_files = ["policies/core.rpol"]"#,
        r#"rpol_files = ["policies/core.rpol", "policies/dup.rpol"]"#,
    );
    fs::write(&toml_path, toml).unwrap();
    let error = load_dir(&dir).expect_err("cross-file collision must fail the load");
    assert!(error.contains("bogon-filter"), "{error}");
    assert!(error.contains("already defined"), "{error}");
}

#[test]
fn rpol_chain_reference_arity_and_argument_errors() {
    // Missing required argument.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""customer-in""#))
        .expect_err("arity error must fail the load");
    assert!(error.contains("takes 1 parameter(s), 0 given"), "{error}");
    // Extra argument on a zero-param policy.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""bogon-filter(1)""#))
        .expect_err("arity error must fail the load");
    assert!(error.contains("takes 0 parameter(s), 1 given"), "{error}");
    // Non-u32 argument.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""customer-in(high)""#))
        .expect_err("argument type error must fail the load");
    assert!(error.contains("is not a u32"), "{error}");
    // Unknown policy.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""nope(1)""#))
        .expect_err("unknown policy must fail the load");
    assert!(error.contains("undefined policy"), "{error}");
}

/// ADR-0076 planner classification: an edited `.rpol` file whose
/// compiled content differs is a `policy_chain` impact for exactly the
/// peers referencing it; reloading unchanged content is a no-op.
#[test]
fn rpol_edit_classifies_policy_chain_impact_for_referencing_peers_only() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""customer-in(200)""#);
    let old = load_dir(&dir).expect("initial load");

    // Same content reloaded → no diff at all.
    let same = load_dir(&dir).expect("reload");
    let diff = diff_config(&old, &same);
    assert!(!diff.policy.rpol_changed);
    assert!(!diff.has_any_changes(), "{diff:?}");

    // Edited file, materially different compiled content.
    fs::write(
        dir.path().join("policies/core.rpol"),
        RPOL_SOURCE.replace("ge 24 le 28", "ge 24 le 32"),
    )
    .unwrap();
    let new = load_dir(&dir).expect("reload after edit");
    let diff = diff_config(&old, &new);
    assert!(diff.policy.rpol_changed);
    assert!(diff.has_reload_applied_changes());
    // Exactly the referencing neighbor is impacted, as a pure
    // policy-chain move (live-impact executor eligible).
    assert_eq!(diff.effective_neighbor_impact.len(), 1);
    let impact = &diff.effective_neighbor_impact[0];
    assert_eq!(impact.address, "192.0.2.1");
    assert!(impact.kind.is_policy_chain());
    assert!(
        impact
            .reasons
            .iter()
            .any(|r| r == "rpol policy file changed"),
        "{:?}",
        impact.reasons
    );
    // v1 transactions cannot stage .rpol content — fail closed.
    let class = classify_config_transaction_v1(&diff);
    assert!(
        class
            .unsupported_sections
            .iter()
            .any(|s| s.contains("rpol_files")),
        "{class:?}"
    );

    // Comment-only edits compile to identical content → the resolved
    // chains compare equal, but the source-level registry diff still
    // reports the file as changed (refresh is idempotent).
    fs::write(
        dir.path().join("policies/core.rpol"),
        format!("# comment\n{RPOL_SOURCE}"),
    )
    .unwrap();
    let commented = load_dir(&dir).expect("reload after comment edit");
    let diff = diff_config(&old, &commented);
    assert!(diff.policy.rpol_changed);
    // No resolved chain moved, so no per-neighbor impact.
    assert!(diff.effective_neighbor_impact.is_empty(), "{diff:?}");
}

// ── RFC 9687 send hold timer config ─────────────────────────────

#[test]
fn send_hold_time_default_is_rfc9687_section6() {
    // hold_time 90 → max(480, 180) = 480 (8 minutes).
    let config = parse(valid_toml()).unwrap();
    assert_eq!(config.neighbors[0].send_hold_time, None);
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers[0].0.peer.send_hold_time, 480);
}

#[test]
fn send_hold_time_default_scales_with_large_hold_time() {
    // hold_time 300 → max(480, 600) = 600.
    let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 300");
    let peers = parse(&toml_str).unwrap().to_peer_configs().unwrap();
    assert_eq!(peers[0].0.peer.send_hold_time, 600);
}

#[test]
fn send_hold_time_explicit_value_applies() {
    let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 90\nsend_hold_time = 120");
    let peers = parse(&toml_str).unwrap().to_peer_configs().unwrap();
    assert_eq!(peers[0].0.peer.send_hold_time, 120);
}

#[test]
fn send_hold_time_zero_disables() {
    let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 90\nsend_hold_time = 0");
    let peers = parse(&toml_str).unwrap().to_peer_configs().unwrap();
    assert_eq!(peers[0].0.peer.send_hold_time, 0);
}

#[test]
fn send_hold_time_not_greater_than_hold_time_rejected() {
    // RFC 9687 §4.4: non-zero SendHoldTime MUST be > HoldTime.
    let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 90\nsend_hold_time = 90");
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidSendHoldTime {
            value: 90,
            hold_time: 90
        }
    ));
}

#[test]
fn send_hold_time_group_inherited_and_validated_against_neighbor_hold_time() {
    // Group supplies send_hold_time = 100; the neighbor overrides
    // hold_time to 120, making the effective pair invalid.
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.transit]
send_hold_time = 100

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "transit"
hold_time = 120
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidSendHoldTime {
            value: 100,
            hold_time: 120
        }
    ));
}

#[test]
fn send_hold_time_group_inheritance_applies() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.transit]
send_hold_time = 900

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "transit"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let resolved = config.resolve_neighbor(&config.neighbors[1]).unwrap();
    assert_eq!(resolved.transport_config.peer.send_hold_time, 900);
}

#[test]
fn send_hold_time_change_is_a_runtime_neighbor_change() {
    // Reload classification matches hold_time: a changed send_hold_time
    // reports the neighbor as changed (session restart applies it).
    let config = parse(valid_toml()).unwrap();
    let old = config.neighbors[0].clone();
    let mut new = old.clone();
    new.send_hold_time = Some(600);
    let diff = super::diff_neighbors(std::slice::from_ref(&old), std::slice::from_ref(&new));
    assert_eq!(diff.changed.len(), 1);
    let changes = super::describe_neighbor_changes(&old, &new);
    assert!(
        changes
            .iter()
            .any(|c| c.render().contains("send_hold_time")),
        "{changes:?}"
    );
}

// ── Retired config keys (LAN-194 removal wave) ──────

/// `MakeWriter` capturing tracing output into a shared buffer so the
/// deprecation-warning tests can assert on emitted (or absent) warns.
#[derive(Clone, Default)]
struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_warnings(f: impl FnOnce()) -> String {
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = writer.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn retired_global_inline_policy_fails_load_with_migration_error() {
    let toml_str = format!(
        "{}\n[[policy.import]]\nprefix = \"10.0.0.0/8\"\nge = 8\nle = 24\naction = \"permit\"\n",
        valid_toml()
    );
    let err = Config::load_toml_with_diagnostics(&toml_str, "test.toml").unwrap_err();
    assert!(
        err.contains("has been removed"),
        "must say the surface is removed: {err}"
    );
    assert!(
        err.contains("[[policy.import]]") && err.contains("[[policy.export]]"),
        "must name the retired keys: {err}"
    );
    assert!(
        err.contains("import_chain") && err.contains("rpol"),
        "must point at the migration targets: {err}"
    );
}

#[test]
fn per_neighbor_inline_policy_still_loads() {
    // Per-neighbor and per-group inline policy is NOT removed — only
    // the global fallback is.
    let toml_str = format!(
        "{}\nimport_policy = [{{ prefix = \"10.0.0.0/8\", ge = 8, le = 32, action = \"permit\" }}]\n",
        valid_toml()
    );
    let config = Config::load_toml_with_diagnostics(&toml_str, "test.toml").unwrap();
    assert!(!config.neighbors[0].import_policy.is_empty());
}

// ── In-daemon looking glass removal (Item: surface reduction) ────────

#[test]
fn retired_looking_glass_fails_load_with_migration_error() {
    let toml_str = format!(
        "{}\n[global.telemetry.looking_glass]\naddr = \"127.0.0.1:8080\"\n",
        valid_toml()
    );
    let err = Config::load_toml_with_diagnostics(&toml_str, "test.toml").unwrap_err();
    assert!(
        err.contains("has been removed"),
        "must say the surface is removed: {err}"
    );
    assert!(
        err.contains("[global.telemetry.looking_glass]"),
        "must name the retired key: {err}"
    );
    assert!(
        err.contains("birdwatcher-adapter"),
        "must point at the external adapter: {err}"
    );
}

// ── Legacy gRPC enforcement sunset warning ───────────────────────────

#[test]
fn legacy_grpc_enforcement_warns_at_startup() {
    // `parse()` injects `enforcement = "legacy"` for fixtures without
    // an explicit [security.grpc] table.
    let config = parse(valid_toml()).unwrap();
    let output = capture_warnings(|| config.warn_if_legacy_grpc_enforcement());
    assert!(
        output.contains("WARN") && output.contains("legacy"),
        "expected a warn-level legacy-enforcement log: {output}"
    );
    assert!(
        output.contains("mandatory in a future release"),
        "warning must name the sunset: {output}"
    );
}

#[test]
fn tier_grpc_enforcement_does_not_warn() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"local-admin\" = \"operator\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml_no_grpc_security()
    );
    let config = parse(&toml_str).unwrap();
    let output = capture_warnings(|| config.warn_if_legacy_grpc_enforcement());
    assert!(output.is_empty(), "no warning expected: {output}");
}

/// The committed JSON Schema must stay in sync with the config structs.
/// `BLESS=1` rewrites the committed file (review the diff), mirroring the
/// diff-golden convention.
#[test]
fn config_json_schema_committed_copy_is_fresh() {
    let generated = config_json_schema();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/rustbgpd.schema.json");
    if std::env::var_os("BLESS").is_some() {
        fs::write(path, &generated).unwrap();
    }
    let committed = fs::read_to_string(path).unwrap();
    assert_eq!(
        generated, committed,
        "docs/rustbgpd.schema.json is stale — regenerate with `cargo run --bin rustbgpd -- \
         --dump-config-schema > docs/rustbgpd.schema.json` (or rerun this test with BLESS=1)"
    );
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

[security.grpc]
enforcement = "legacy"

[policy]
rpol_files = ["policies/core.rpol"]

[policy.datasets.customers]
path = "datasets/customers.list"

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = ["origin-guard"]
"#;
    fs::write(dir.path().join("config.toml"), toml).expect("write config");
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

/// Initial load: declaration + `[policy.datasets]` binding + file →
/// a generation-1 handle, chains resolve and probe it.
#[test]
fn dataset_binds_at_load_and_chains_probe_it() {
    let dir = dataset_config_dir("# customers\n64500\n");
    let config = load_dir(&dir).expect("config with a dataset loads");
    let handle = config
        .policy
        .dataset_bindings
        .get("customers")
        .expect("bound");
    assert_eq!(handle.pin().generation, 1);
    assert!(config.policy.dataset_events.swapped.is_empty());

    let (import, _) = config
        .effective_policy_chains_for_neighbor(&config.neighbors[0])
        .expect("chains resolve");
    let import = import.expect("import chain configured");
    assert!(import.references_dataset("customers"));
    assert_eq!(
        import.evaluate(&origin_ctx(64500)).action,
        rustbgpd_policy::PolicyAction::Permit
    );
    assert_eq!(
        import.evaluate(&origin_ctx(64999)).action,
        rustbgpd_policy::PolicyAction::Deny
    );
}

/// Both directions of declaration ↔ binding coverage, and an
/// unreadable file at initial load, are load errors.
#[test]
fn dataset_binding_validation_rejects_mismatches() {
    // Declared but no [policy.datasets] entry.
    let dir = dataset_config_dir("64500\n");
    let toml = fs::read_to_string(dir.path().join("config.toml")).unwrap();
    fs::write(
        dir.path().join("config.toml"),
        toml.replace(
            "[policy.datasets.customers]\npath = \"datasets/customers.list\"\n",
            "",
        ),
    )
    .unwrap();
    let err = load_dir(&dir).expect_err("missing binding entry");
    assert!(
        err.contains("has no [policy.datasets.customers] entry"),
        "{err}"
    );

    // Entry without a declaration.
    let dir = dataset_config_dir("64500\n");
    let toml = fs::read_to_string(dir.path().join("config.toml")).unwrap();
    fs::write(
        dir.path().join("config.toml"),
        toml.replace(
            "[policy.datasets.customers]\npath = \"datasets/customers.list\"",
            "[policy.datasets.customers]\npath = \"datasets/customers.list\"\n\n\
             [policy.datasets.orphan]\npath = \"datasets/customers.list\"",
        ),
    )
    .unwrap();
    let err = load_dir(&dir).expect_err("orphan binding entry");
    assert!(
        err.contains("does not match any `dataset` declaration"),
        "{err}"
    );

    // Initial load with an unparseable file: hard error (no prior
    // snapshot exists to keep).
    let dir = dataset_config_dir("not-an-asn\n");
    let err = load_dir(&dir).expect_err("bad file at initial load");
    assert!(err.contains("line 1"), "{err}");
}

/// The SIGHUP shape (`load_with_diagnostics_and_datasets`): declared
/// datasets reuse the running handles — changed content swaps in
/// place (generation bump + `dataset_events.swapped`), content-equal
/// re-reads are no-ops, and a bad file keeps the prior snapshot with
/// the error recorded instead of rejecting the reload. Chain identity
/// is untouched throughout (the #775 content-equal reinstall skip
/// sees no change).
#[test]
fn dataset_reload_reuses_handles_swaps_scoped_and_keeps_prior_on_failure() {
    let dir = dataset_config_dir("64500\n");
    let path = dir.path().join("config.toml");
    let path = path.to_str().unwrap();
    let initial = Config::load_with_diagnostics(path).expect("initial load");
    let handle = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
    let (chain_before, _) = initial
        .effective_policy_chains_for_neighbor(&initial.neighbors[0])
        .expect("chains resolve");

    // Content change: same handle, generation bump, swapped recorded.
    fs::write(dir.path().join("datasets/customers.list"), "64500\n64999\n").unwrap();
    let reloaded =
        Config::load_with_diagnostics_and_datasets(path, Some(&initial.policy.dataset_bindings))
            .expect("reload with changed dataset");
    assert!(std::sync::Arc::ptr_eq(
        &handle,
        reloaded.policy.dataset_bindings.get("customers").unwrap()
    ));
    assert_eq!(handle.pin().generation, 2);
    assert_eq!(reloaded.policy.dataset_events.swapped, vec!["customers"]);
    assert!(reloaded.policy.dataset_events.failed.is_empty());
    // The chain installed from the OLD config now permits the new
    // member — the swap reached it without any reinstall — and the
    // re-resolved chain is content-equal (no Route Refresh storm).
    let chain_before = chain_before.expect("import chain");
    assert_eq!(
        chain_before.evaluate(&origin_ctx(64999)).action,
        rustbgpd_policy::PolicyAction::Permit
    );
    let (chain_after, _) = reloaded
        .effective_policy_chains_for_neighbor(&reloaded.neighbors[0])
        .expect("chains resolve");
    assert_eq!(Some(&chain_before), chain_after.as_ref());

    // Content-equal re-read (reordered + comments): no swap, no event.
    fs::write(
        dir.path().join("datasets/customers.list"),
        "# reordered\n64999\n64500\n",
    )
    .unwrap();
    let unchanged =
        Config::load_with_diagnostics_and_datasets(path, Some(&reloaded.policy.dataset_bindings))
            .expect("content-equal reload");
    assert_eq!(handle.pin().generation, 2);
    assert!(unchanged.policy.dataset_events.swapped.is_empty());

    // Bad file: reload still succeeds, prior snapshot retained, error
    // surfaced on the handle and in the events.
    fs::write(
        dir.path().join("datasets/customers.list"),
        "garbage entry\n",
    )
    .unwrap();
    let failed =
        Config::load_with_diagnostics_and_datasets(path, Some(&unchanged.policy.dataset_bindings))
            .expect("reload survives a bad dataset file");
    assert_eq!(handle.pin().generation, 2, "prior snapshot retained");
    assert_eq!(failed.policy.dataset_events.failed.len(), 1);
    assert_eq!(failed.policy.dataset_events.failed[0].0, "customers");
    let status = handle.status();
    assert!(status.last_error.is_some(), "{status:?}");
    assert_eq!(
        failed
            .policy
            .dataset_bindings
            .get("customers")
            .unwrap()
            .pin()
            .data
            .records(),
        2,
        "old data still probing"
    );
}

#[test]
fn staged_dataset_reload_defers_live_handle_mutation_until_commit() {
    let dir = dataset_config_dir("64500\n");
    let path = dir.path().join("config.toml");
    let path = path.to_str().unwrap();
    let initial = Config::load_with_diagnostics(path).expect("initial load");
    let live = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());

    fs::write(dir.path().join("datasets/customers.list"), "64500\n64999\n").unwrap();
    let mut staged =
        Config::load_with_diagnostics_and_staged_datasets(path, &initial.policy.dataset_bindings)
            .expect("stage changed dataset");

    assert_eq!(live.pin().generation, 1);
    assert_eq!(live.pin().data.records(), 1);
    assert_eq!(staged.policy.dataset_events.swapped, vec!["customers"]);
    assert!(!std::sync::Arc::ptr_eq(
        &live,
        staged.policy.dataset_bindings.get("customers").unwrap()
    ));

    let commit = staged.prepare_staged_datasets(&initial.policy.dataset_bindings);
    assert!(std::sync::Arc::ptr_eq(
        &live,
        staged.policy.dataset_bindings.get("customers").unwrap()
    ));
    assert_eq!(live.pin().generation, 1);
    commit.commit();
    assert_eq!(live.pin().generation, 2);
    assert_eq!(live.pin().data.records(), 2);

    fs::write(
        dir.path().join("datasets/customers.list"),
        "garbage entry\n",
    )
    .unwrap();
    let mut failed =
        Config::load_with_diagnostics_and_staged_datasets(path, &staged.policy.dataset_bindings)
            .expect("stage failed refresh against prior snapshot");
    assert_eq!(failed.policy.dataset_events.failed.len(), 1);
    assert!(live.status().last_error.is_none());
    assert_eq!(live.pin().generation, 2);

    let commit = failed.prepare_staged_datasets(&staged.policy.dataset_bindings);
    assert!(live.status().last_error.is_none());
    commit.commit();
    assert!(live.status().last_error.is_some());
    assert_eq!(live.pin().generation, 2);
    assert_eq!(live.pin().data.records(), 2);
}

// ---------------------------------------------------------------------------
// Effective running config dump (`rbgp config effective`, LAN-325)
// ---------------------------------------------------------------------------

#[test]
fn effective_redacted_materializes_neighbor_defaults() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
    let config = Config::load_toml_with_diagnostics(toml_str, "test.toml").unwrap();
    let rendered = config.effective_redacted_toml().unwrap();

    // Computed defaults appear as concrete values: DEFAULT_HOLD_TIME and
    // the RFC 9687 §6 derived send-hold default (max(480, 2 × hold)).
    assert!(rendered.contains("hold_time = 90"), "{rendered}");
    assert!(rendered.contains("send_hold_time = 480"), "{rendered}");
    assert!(rendered.contains("graceful_restart = true"), "{rendered}");
    assert!(
        rendered.contains("gr_peer_restart_time_max = 4095"),
        "{rendered}"
    );
    assert!(rendered.contains("gr_restart_time = 120"), "{rendered}");
    assert!(
        rendered.contains("gr_stale_routes_time = 360"),
        "{rendered}"
    );
    assert!(rendered.contains("llgr_stale_time = 0"), "{rendered}");
    assert!(rendered.contains("ttl_security = false"), "{rendered}");
    assert!(rendered.contains("\"ipv4_unicast\""), "{rendered}");
}

#[test]
fn effective_redacted_matches_resolve_neighbor() {
    // Drift guard: the materialization constants in `effective_redacted`
    // must agree with `resolve_neighbor` for both a bare neighbor and a
    // group-inheriting neighbor.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.rr-clients]
hold_time = 30
gr_restart_time = 200

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65001
peer_group = "rr-clients"
"#;
    let config = Config::load_toml_with_diagnostics(toml_str, "test.toml").unwrap();
    let effective = config.effective_redacted();
    for (original, materialized) in config.neighbors.iter().zip(&effective.neighbors) {
        let resolved = config.resolve_neighbor(original).unwrap();
        let peer = &resolved.transport_config.peer;
        assert_eq!(materialized.hold_time, Some(peer.hold_time));
        assert_eq!(materialized.send_hold_time, Some(peer.send_hold_time));
        assert_eq!(materialized.graceful_restart, Some(peer.graceful_restart));
        assert_eq!(materialized.gr_restart_time, Some(peer.gr_restart_time));
        assert_eq!(
            materialized.gr_peer_restart_time_max,
            Some(resolved.transport_config.gr_peer_restart_time_max)
        );
        assert_eq!(
            materialized.gr_stale_routes_time,
            Some(resolved.transport_config.gr_stale_routes_time)
        );
        assert_eq!(
            materialized.llgr_stale_time,
            Some(resolved.transport_config.llgr_stale_time)
        );
        assert_eq!(
            materialized.ttl_security,
            Some(resolved.transport_config.ttl_security)
        );
    }
    // Group inheritance visible on the second neighbor.
    assert_eq!(effective.neighbors[1].hold_time, Some(30));
    assert_eq!(effective.neighbors[1].gr_restart_time, Some(200));
}

#[test]
fn effective_redacted_never_leaks_secrets() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.md5-group]
md5_password = "group-hunter2-seed"

[peer_groups.dynamic]
hold_time = 90

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "dynamic"
tcp_ao = { key = "dynamic-hunter2-seed", send_id = 3, recv_id = 4, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "neighbor-hunter2-seed"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003

[neighbors.tcp_ao]
key = "tcp-ao-hunter2-seed"
send_id = 1
recv_id = 2
algorithm = "hmac(sha256)"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65001
peer_group = "md5-group"
"#;
    let config = Config::load_toml_with_diagnostics(toml_str, "test.toml").unwrap();
    let rendered = config.effective_redacted_toml().unwrap();
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains(REDACTED_SECRET), "{rendered}");
}

#[test]
fn effective_redacted_toml_is_deterministic_and_round_trips() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.zeta]
hold_time = 15

[peer_groups.alpha]
hold_time = 45

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
peer_group = "alpha"

[[neighbors]]
address = "2001:db8::2"
remote_asn = 65002
"#;
    let config = Config::load_toml_with_diagnostics(toml_str, "test.toml").unwrap();
    let first = config.effective_redacted_toml().unwrap();
    let second = config.effective_redacted_toml().unwrap();
    assert_eq!(first, second, "effective dump must be deterministic");

    // Secretless dumps round-trip through the normal loader + validator.
    let reloaded = Config::load_toml_with_diagnostics(&first, "effective.toml")
        .expect("secretless effective dump must reload cleanly");
    assert_eq!(reloaded.neighbors[0].hold_time, Some(45));
    // Implicit-family default for the IPv6 neighbor is materialized.
    let v6 = reloaded
        .neighbors
        .iter()
        .find(|n| n.address == "2001:db8::2")
        .unwrap();
    assert_eq!(
        v6.families,
        vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()]
    );

    // Reloading the dump and dumping again is a fixpoint.
    assert_eq!(reloaded.effective_redacted_toml().unwrap(), first);
}

#[test]
fn redacted_placeholder_fails_validation_loudly() {
    for (label, snippet) in [
        (
            "neighbor md5",
            "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\nmd5_password = \"<redacted>\"\n",
        ),
        (
            "tcp_ao key",
            "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n[neighbors.tcp_ao]\nkey = \"<redacted>\"\nsend_id = 1\nrecv_id = 2\nalgorithm = \"hmac(sha256)\"\n",
        ),
        (
            "peer group md5",
            "[peer_groups.g]\nmd5_password = \"<redacted>\"\n",
        ),
        (
            "dynamic tcp_ao key",
            "[peer_groups.g]\nhold_time = 90\n[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"g\"\ntcp_ao = { key = \"<redacted>\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }\n",
        ),
    ] {
        let toml_str = format!(
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n[global.telemetry]\nlog_format = \"json\"\n\n{snippet}"
        );
        let err = Config::load_toml_with_diagnostics(&toml_str, "effective.toml").expect_err(label);
        assert!(err.contains("rbgp config effective"), "{label}: {err}");
    }
}

#[test]
fn effective_redacted_dump_with_secrets_does_not_reload() {
    // The documented contract: a dump taken from a secret-bearing config
    // must fail --check/load loudly rather than boot with the placeholder.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "hunter2"
"#;
    let config = Config::load_toml_with_diagnostics(toml_str, "test.toml").unwrap();
    let rendered = config.effective_redacted_toml().unwrap();
    let err = Config::load_toml_with_diagnostics(&rendered, "effective.toml").unwrap_err();
    assert!(err.contains("md5_password"), "{err}");
}
