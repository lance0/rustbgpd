use super::*;

#[test]
fn invalid_router_id_rejected() {
    let toml_str = valid_toml().replace("10.0.0.1", "not-an-ip");
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouterId { .. }));
}

#[test]
fn local_as_zero_is_rejected() {
    // Mutation-red: removing the global ASN predicate makes this fixture parse.
    let toml_str = valid_toml().replace("asn = 65001", "asn = 0");
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidLocalAsn { value: 0 }));
}

#[test]
fn local_router_id_zero_is_rejected() {
    // Mutation-red: removing the non-zero router-ID predicate makes this fixture parse.
    let toml_str = valid_toml().replace("router_id = \"10.0.0.1\"", "router_id = \"0.0.0.0\"");
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouterId { .. }));
    assert!(err.to_string().contains("must be non-zero"));
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
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end inheritance and negotiation matrix keeps the floor contract coherent"
)]
fn minimum_hold_time_validates_effective_static_and_group_values() {
    // Mutation-red: deleting validation accepts invalid pairs; deleting the
    // resolver assignment loses static inheritance and dynamic OPEN 2/6.
    let below_range =
        parse(&valid_toml().replace("hold_time = 90", "hold_time = 90\nmin_hold_time = 2"))
            .unwrap_err();
    assert!(matches!(
        below_range,
        ConfigError::InvalidMinHoldTime { value: 2 }
    ));

    for (hold_time, minimum) in [(0, 30), (30, 31)] {
        let invalid = parse(&valid_toml().replace(
            "hold_time = 90",
            &format!("hold_time = {hold_time}\nmin_hold_time = {minimum}"),
        ))
        .unwrap_err();
        assert!(matches!(
            invalid,
            ConfigError::InvalidMinHoldTimeForHoldTime {
                minimum: actual_minimum,
                hold_time: actual_hold
            } if actual_minimum == minimum && actual_hold == hold_time
        ));
    }

    let inherited_invalid = format!(
        r#"
{GLOBAL_HEADER}
[peer_groups.clients]
min_hold_time = 30
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "clients"
hold_time = 20
"#,
        GLOBAL_HEADER = valid_toml()
    );
    assert!(matches!(
        parse(&inherited_invalid).unwrap_err(),
        ConfigError::InvalidMinHoldTimeForHoldTime {
            minimum: 30,
            hold_time: 20
        }
    ));

    let inherited = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.clients]
min_hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "clients"
hold_time = 45

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
peer_group = "clients"
hold_time = 45
min_hold_time = 20

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "clients"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&inherited).unwrap();
    assert_eq!(
        config
            .resolve_neighbor(&config.neighbors[1])
            .unwrap()
            .transport_config
            .peer
            .min_hold_time,
        Some(30)
    );
    assert_eq!(
        config
            .resolve_neighbor(&config.neighbors[2])
            .unwrap()
            .transport_config
            .peer
            .min_hold_time,
        Some(20)
    );
    let group = &config.peer_groups["clients"];
    let dynamic = config
        .resolve_dynamic_neighbor(
            "192.0.2.1".parse().unwrap(),
            65005,
            "dynamic",
            group,
            "clients",
            false,
        )
        .unwrap();
    assert_eq!(dynamic.transport_config.peer.min_hold_time, Some(30));

    let mut open = rustbgpd_wire::OpenMessage {
        version: 4,
        my_as: 65005,
        hold_time: 29,
        bgp_identifier: "192.0.2.1".parse().unwrap(),
        capabilities: Vec::new(),
    };
    let err = rustbgpd_fsm::negotiation::validate_open(&open, &dynamic.transport_config.peer)
        .unwrap_err();
    assert_eq!(
        err.subcode,
        rustbgpd_wire::notification::open_subcode::UNACCEPTABLE_HOLD_TIME
    );
    open.hold_time = 30;
    assert!(
        rustbgpd_fsm::negotiation::validate_open(&open, &dynamic.transport_config.peer).is_ok()
    );
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
fn listen_addrs_cover_both_families() {
    // LAN-907: the BGP listener serves both address families at
    // `listen_port`; there is no listen-address knob.
    let config = parse(valid_toml()).unwrap();
    let (v4, v6) = config.listen_addrs();
    assert_eq!(v4, "0.0.0.0:179".parse::<SocketAddr>().unwrap());
    assert_eq!(v6, "[::]:179".parse::<SocketAddr>().unwrap());
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

#[test]
fn inbound_admission_defaults_off_and_validates_bounds() {
    // ADR-0120: opt-in — a config without the table parses with the
    // limiter disabled and the documented defaults.
    let default = parse(valid_toml()).unwrap();
    assert!(!default.inbound_admission.enabled);
    assert_eq!(default.inbound_admission.rate_per_minute, 12);
    assert_eq!(default.inbound_admission.burst, 5);
    assert_eq!(default.inbound_admission.v4_aggregation_len, 32);
    assert_eq!(default.inbound_admission.v6_aggregation_len, 64);
    assert_eq!(default.inbound_admission.table_capacity, 4096);

    let enabled = |extra: &str| {
        parse(&format!(
            "{}\n[inbound_admission]\nenabled = true\n{extra}\n",
            valid_toml()
        ))
    };
    assert!(enabled("").is_ok());
    for (rejected, needle) in [
        ("rate_per_minute = 0", "rate_per_minute"),
        ("burst = 0", "burst"),
        ("v4_aggregation_len = 7", "v4_aggregation_len"),
        ("v4_aggregation_len = 33", "v4_aggregation_len"),
        ("v6_aggregation_len = 15", "v6_aggregation_len"),
        ("v6_aggregation_len = 129", "v6_aggregation_len"),
        ("table_capacity = 63", "table_capacity"),
        ("table_capacity = 65537", "table_capacity"),
    ] {
        let error = enabled(rejected).unwrap_err().to_string();
        assert!(
            error.contains("inbound_admission") && error.contains(needle),
            "{rejected}: {error}"
        );
    }
    // Bounds are enforced only when enabled — a disabled table with
    // out-of-range values still parses (the limiter is never built).
    assert!(
        parse(&format!(
            "{}\n[inbound_admission]\nrate_per_minute = 0\n",
            valid_toml()
        ))
        .is_ok()
    );
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

// ── Expired retired-key pointers (ADR-0122) ─────────

#[test]
fn retired_global_inline_policy_uses_generic_unknown_field_error() {
    let toml_str = format!(
        "{}\n[[policy.import]]\nprefix = \"10.0.0.0/8\"\nge = 8\nle = 24\naction = \"permit\"\n",
        valid_toml()
    );
    let err = Config::load_toml_with_diagnostics(&toml_str, "test.toml").unwrap_err();
    assert!(
        err.contains("unknown field") && err.contains("import"),
        "must use the ordinary typed-config diagnostic: {err}"
    );
    assert!(
        !err.contains("global inline policy fallback")
            && !err.contains("Named policy definitions")
            && !err.contains("Per-neighbor and per-group"),
        "the expired bespoke migration pointer must stay removed: {err}"
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
    let config = Config::load_toml_with_diagnostics(
        &tier_authorized_uds_test_config(&toml_str),
        "test.toml",
    )
    .unwrap();
    assert!(!config.neighbors[0].import_policy.is_empty());
}

// ── In-daemon looking glass pointer expiry ───────────────────────────

#[test]
fn retired_looking_glass_uses_generic_unknown_field_error() {
    let toml_str = format!(
        "{}\n[global.telemetry.looking_glass]\naddr = \"127.0.0.1:8080\"\n",
        valid_toml()
    );
    let err = Config::load_toml_with_diagnostics(&toml_str, "test.toml").unwrap_err();
    assert!(
        err.contains("unknown field") && err.contains("looking_glass"),
        "must use the ordinary typed-config diagnostic: {err}"
    );
    assert!(
        !err.contains("birdwatcher-adapter") && !err.contains("has been removed"),
        "the expired bespoke migration pointer must stay removed: {err}"
    );
}
