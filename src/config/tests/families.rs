use super::*;

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
