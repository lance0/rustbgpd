use super::*;

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
    let reparsed = parse_strict(&rendered).unwrap();
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
fn orr_vantage_without_linkstate_raises_an_advisory() {
    let toml = orr_toml(
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true",
        "",
    );
    let config = parse(&toml).unwrap();
    let advisory = config
        .advisories()
        .into_iter()
        .find(|a| a.headline.contains("orr_vantage"))
        .expect("an unresolvable vantage must raise an advisory");
    let text = advisory.one_line();
    // Condition, consequence, action.
    assert!(
        text.contains("linkstate"),
        "advisory must name the missing family: {text}"
    );
    assert!(
        text.contains("stays unresolved") && text.contains("no effect"),
        "advisory must name the consequence: {text}"
    );
    assert!(
        text.contains("Add \"linkstate\" to the families"),
        "advisory must give the action: {text}"
    );
    // One line, so a log record stays one record.
    assert!(!text.contains('\n'), "one_line kept a newline: {text}");

    // Static peer-group inheritance raises the identical final advisory.
    let inherited = parse(&orr_toml(
        "",
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true",
    ))
    .unwrap();
    assert_eq!(inherited.advisories(), vec![advisory]);

    // Cleared once a neighbor carries the feed.
    let toml = orr_toml(
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true\nfamilies = [\"ipv4_unicast\", \"linkstate\"]",
        "",
    );
    let config = parse(&toml).unwrap();
    assert!(config.advisories().is_empty(), "{:?}", config.advisories());
}

#[test]
fn orr_advisory_accounts_for_dynamic_peer_group_topology() {
    // Load-bearing metamorphic matrix: removing dynamic-range enumeration
    // misses the dynamic-only warning and the dynamic feed, while adding a
    // static feed to the same dynamic vantage must clear the warning.
    let vantage = "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true";
    let vantage_and_feed = format!("{vantage}\nfamilies = [\"linkstate\"]");
    let cases = [
        ("dynamic vantage without feed warns", "", vantage, true),
        (
            "dynamic vantage with static feed clears",
            "families = [\"linkstate\"]",
            vantage,
            false,
        ),
        (
            "static vantage with dynamic feed clears",
            vantage,
            "families = [\"linkstate\"]",
            false,
        ),
        (
            "dynamic vantage with dynamic feed clears",
            "",
            &vantage_and_feed,
            false,
        ),
    ];
    for (case, static_fields, dynamic_fields, expected) in cases {
        let config = parse(&orr_dynamic_toml(static_fields, dynamic_fields)).unwrap();
        let advisories = config.advisories();
        let actual = advisories
            .iter()
            .any(|advisory| advisory.headline.contains("orr_vantage"));
        assert_eq!(actual, expected, "{case}: {advisories:?}");
    }
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
