use super::*;

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
    assert_eq!(
        peers[0].0.ttl_security_hops,
        std::num::NonZeroU8::new(1),
        "the legacy boolean remains an exact-255 one-hop policy"
    );
}

#[test]
fn ttl_security_hops_inherit_override_and_require_enablement() {
    let inherited = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.multihop]
ttl_security = true
ttl_security_hops = 9

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "multihop"
"#;
    let config = parse(inherited).unwrap();
    assert_eq!(
        config.to_peer_configs().unwrap()[0].0.ttl_security_hops,
        std::num::NonZeroU8::new(9)
    );

    let overridden = inherited.replace(
        "peer_group = \"multihop\"",
        "peer_group = \"multihop\"\nttl_security_hops = 3",
    );
    assert_eq!(
        parse(&overridden).unwrap().to_peer_configs().unwrap()[0]
            .0
            .ttl_security_hops,
        std::num::NonZeroU8::new(3)
    );

    let disabled_neighbor = overridden.replace(
        "ttl_security_hops = 3",
        "ttl_security = false\nttl_security_hops = 3",
    );
    assert!(parse(&disabled_neighbor).is_err());

    let inherited_disabled = inherited.replace(
        "peer_group = \"multihop\"",
        "peer_group = \"multihop\"\nttl_security = false",
    );
    let config = parse(&inherited_disabled).unwrap();
    assert_eq!(
        config.to_peer_configs().unwrap()[0].0.ttl_security_hops,
        None
    );
    assert_eq!(
        config.effective_redacted().neighbors[0].ttl_security_hops,
        None
    );

    let disabled_group = inherited.replace("ttl_security = true", "ttl_security = false");
    assert!(parse(&disabled_group).is_err());

    let zero = inherited.replace("ttl_security_hops = 9", "ttl_security_hops = 0");
    assert!(parse(&zero).is_err());
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
fn received_max_prefixes_inherit_from_group_and_override_per_neighbor() {
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
max_prefixes_received_ipv4 = 120
max_prefixes_received_ipv6 = 60

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
max_prefixes_received_ipv4 = 12
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.max_prefixes_received_ipv4,
        Some(12),
        "neighbor-level value overrides the group"
    );
    assert_eq!(
        peers[0].0.max_prefixes_received_ipv6,
        Some(60),
        "unset neighbor value inherits from the group"
    );
    assert_eq!(
        peers[0].0.max_prefixes_ipv4,
        Some(100),
        "the accepted-route bound is independent of the received one"
    );
    assert_eq!(peers[0].0.max_prefixes_ipv6, None);
}

#[test]
fn received_max_prefixes_reject_non_u32_values() {
    for value in ["-1", "\"12\"", "4294967296", "1.5"] {
        let toml_str = format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
max_prefixes_received_ipv4 = {value}
"#
        );
        assert!(parse(&toml_str).is_err(), "{value} must be rejected");
    }
}

#[test]
fn received_max_prefix_edit_is_hot_applicable() {
    let old = test_neighbor("10.0.0.2", 65002);
    let mut hot = old.clone();
    hot.max_prefixes_received_ipv4 = Some(10);
    hot.max_prefixes_received_ipv6 = Some(20);
    assert!(super::neighbor_change_hot_applicable(&old, &hot));
    let changes = super::describe_neighbor_changes(&old, &hot);
    assert_eq!(changes.len(), 2);
    assert!(
        changes
            .iter()
            .all(|change| change.impact == Some(super::ConfigFieldImpact::HotApplied))
    );
}

fn max_prefix_mode_config(neighbor_extra: &str, group_extra: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ixp-members]
max_prefixes_ipv4 = 100
{group_extra}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ixp-members"
{neighbor_extra}
"#
    )
}

#[test]
fn max_prefix_modes_are_accepted_inherited_and_resolved() {
    let config = parse(&max_prefix_mode_config(
        "",
        "max_prefix_action = \"block\"\nmax_prefix_warning_percent = 80",
    ))
    .unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.max_prefix_action,
        rustbgpd_transport::MaxPrefixAction::Block,
        "group action inherited"
    );
    assert_eq!(peers[0].0.max_prefix_warning_percent, Some(80));

    let config = parse(&max_prefix_mode_config(
        "max_prefix_action = \"warning\"",
        "max_prefix_action = \"block\"",
    ))
    .unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.max_prefix_action,
        rustbgpd_transport::MaxPrefixAction::Warning,
        "neighbor overrides the group"
    );
    assert_eq!(peers[0].0.max_prefix_warning_percent, None);

    // `warning` may coexist with the aggregate and a threshold at the edges.
    for extra in [
        "max_prefixes = 500\nmax_prefix_action = \"warning\"",
        "max_prefix_warning_percent = 1",
        "max_prefix_warning_percent = 100",
        "max_prefix_action = \"shutdown\"\nmax_prefix_restart_seconds = 60",
    ] {
        assert!(
            parse(&max_prefix_mode_config(extra, "")).is_ok(),
            "{extra} must be accepted"
        );
    }
    let config = parse(&max_prefix_mode_config("", "")).unwrap();
    assert_eq!(
        config.to_peer_configs().unwrap()[0].0.max_prefix_action,
        rustbgpd_transport::MaxPrefixAction::Shutdown,
        "absent action keeps the historical shutdown"
    );
}

#[test]
fn max_prefix_modes_reject_unknown_actions_and_conflicting_fields() {
    for (neighbor_extra, group_extra, marker) in [
        ("max_prefix_action = \"drop\"", "", "unknown value \"drop\""),
        ("", "max_prefix_action = \"drop\"", "unknown value \"drop\""),
        (
            "max_prefixes = 500\nmax_prefix_action = \"block\"",
            "",
            "per-family unicast bounds only",
        ),
        (
            "max_prefix_action = \"block\"",
            "max_prefixes = 500",
            "per-family unicast bounds only",
        ),
        (
            "max_prefix_action = \"warning\"\nmax_prefix_restart_seconds = 60",
            "",
            "excludes max_prefix_restart_seconds",
        ),
        (
            "max_prefix_action = \"block\"",
            "max_prefix_restart_seconds = 60",
            "excludes max_prefix_restart_seconds",
        ),
        ("max_prefix_warning_percent = 0", "", "outside 1..=100"),
        ("", "max_prefix_warning_percent = 101", "outside 1..=100"),
        ("max_prefix_warning_percent = 256", "", ""),
    ] {
        let error = match parse(&max_prefix_mode_config(neighbor_extra, group_extra)) {
            Ok(_) => panic!("{neighbor_extra:?} / {group_extra:?} must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(marker),
            "{neighbor_extra:?} / {group_extra:?}: {error}"
        );
    }
}

#[test]
fn max_prefix_mode_edits_are_hot_applicable() {
    let old = test_neighbor("10.0.0.2", 65002);
    let mut hot = old.clone();
    hot.max_prefix_action = Some("warning".to_string());
    hot.max_prefix_warning_percent = Some(90);
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
fn tcp_mss_inherits_from_group_allows_neighbor_override_and_is_restart_required() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.tunnel]
tcp_mss = 1360

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "tunnel"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "tunnel"
tcp_mss = 1200

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
"#;
    let config = parse(toml_str).unwrap();
    let resolved = config.resolved_neighbors().unwrap();
    let mss: Vec<Option<u16>> = resolved
        .iter()
        .map(|neighbor| neighbor.transport_config.tcp_mss)
        .collect();
    assert_eq!(mss, vec![Some(1360), Some(1200), None]);
    assert_eq!(
        config_field_impact("tcp_mss").map(|(impact, _)| impact),
        Some(ConfigFieldImpact::RestartRequired)
    );
    let effective = config.effective_redacted();
    assert_eq!(effective.neighbors[0].tcp_mss, Some(1360));
    assert_eq!(effective.neighbors[1].tcp_mss, Some(1200));
    assert_eq!(effective.neighbors[2].tcp_mss, None);
}

#[test]
fn dynamic_range_rejects_peer_group_tcp_mss() {
    let err = parse(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.dynamic]
tcp_mss = 1360

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "dynamic"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("tcp_mss"), "{err}");
    assert!(err.contains("static neighbors only"), "{err}");
}

#[test]
fn tcp_mss_rejects_values_outside_the_kernel_range() {
    let base = "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[global.telemetry]\nprometheus_addr = \"0.0.0.0:9179\"\nlog_format = \"json\"\n\n";
    for (snippet, expected) in [
        (
            "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\ntcp_mss = 87\n",
            "10.0.0.2: tcp_mss: 87",
        ),
        (
            "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\ntcp_mss = 32768\n",
            "10.0.0.2: tcp_mss: 32768",
        ),
        ("[peer_groups.g]\ntcp_mss = 0\n", "peer_group.g: tcp_mss: 0"),
    ] {
        let err = parse(&format!("{base}{snippet}")).unwrap_err().to_string();
        assert!(err.contains(expected), "{err}");
        assert!(err.contains("88..=32767"), "{err}");
    }
    let ok =
        format!("{base}[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\ntcp_mss = 88\n");
    assert!(parse(&ok).is_ok());
}
