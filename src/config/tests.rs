use super::*;
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
        "0.0.0.0:9179".parse::<SocketAddr>().unwrap()
    );
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
    let toml = community_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(import.policies[0].entries.len(), 1);
    assert_eq!(
        import.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Invalid)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_valid() {
    let toml = community_toml(
        r#"action = "permit"
            match_rpki_validation = "valid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(
        import.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Valid)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_not_found() {
    let toml = community_toml(
        r#"action = "permit"
            match_rpki_validation = "not_found""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(
        import.policies[0].entries[0].match_rpki_validation,
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
    // match_rpki_validation alone (without prefix/community/aspath) should be valid
    let toml = community_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    assert!(parse(&toml).is_ok());
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
