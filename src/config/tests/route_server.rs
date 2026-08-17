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
fn orr_vantage_equal_to_the_neighbor_own_address_is_accepted() {
    // RFC 9107: the vantage IS the client's IGP location, so a
    // client's own address is the canonical value — and the one that
    // `"peer_address"` derives. Only the reflector's own router_id
    // degenerates to plain non-ORR reflection.
    let toml = orr_toml(
        "route_reflector_client = true\norr_vantage = \"10.0.0.2\"",
        "",
    );
    let config = parse(&toml).expect("a client's own address is a valid vantage");
    let resolved = config.resolved_neighbors().unwrap();
    assert_eq!(
        resolved[0].transport_config.orr_vantage,
        Some("10.0.0.2".parse().unwrap()),
        "the literal form resolves to the same value peer_address derives"
    );
}

#[test]
fn orr_vantage_rejected_when_equal_to_local_router_id() {
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
    )
    .replace(
        "listen_port = 179",
        "listen_port = 179\nebgp_requires_policy = false",
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
    let inherited_toml = orr_toml(
        "",
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true",
    )
    .replace(
        "listen_port = 179",
        "listen_port = 179\nebgp_requires_policy = false",
    );
    let inherited = parse(&inherited_toml).unwrap();
    assert_eq!(inherited.advisories(), vec![advisory]);

    // Cleared once a neighbor carries the feed.
    let toml = orr_toml(
        "orr_vantage = \"192.0.2.7\"\nroute_reflector_client = true\nfamilies = [\"ipv4_unicast\", \"linkstate\"]",
        "",
    )
    .replace(
        "listen_port = 179",
        "listen_port = 179\nebgp_requires_policy = false",
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

// --- `orr_vantage = "peer_address"` ---

#[test]
fn parse_orr_vantage_accepts_addresses_and_the_peer_address_sentinel() {
    assert_eq!(
        parse_orr_vantage("192.0.2.7"),
        Ok(OrrVantage::Address("192.0.2.7".parse().unwrap())),
        "a literal IPv4 vantage parses to the address form"
    );
    assert_eq!(
        parse_orr_vantage("2001:db8::7"),
        Ok(OrrVantage::Address("2001:db8::7".parse().unwrap())),
        "a literal IPv6 vantage parses to the address form"
    );
    assert_eq!(
        parse_orr_vantage("peer_address"),
        Ok(OrrVantage::PeerAddress),
        "the canonical snake_case sentinel parses"
    );
    assert_eq!(
        parse_orr_vantage("peer-address"),
        Ok(OrrVantage::PeerAddress),
        "the kebab-case alias parses (BgpRoleConfig rs-client precedent)"
    );

    let err = parse_orr_vantage("not-an-address").unwrap_err();
    assert!(
        err.contains("not-an-address") && err.contains("peer_address"),
        "the reason names the offending value and the sentinel: {err}"
    );
    // Reject near-misses rather than guessing intent.
    assert!(parse_orr_vantage("PEER_ADDRESS").is_err());
    assert!(parse_orr_vantage("").is_err());
}

#[test]
fn orr_vantage_peer_address_resolves_to_each_dynamic_peer_own_address() {
    // The point of the feature: one range, one peer group, one `orr_vantage`
    // value — but every accepted peer lands in its own vantage, because the
    // sentinel resolves against that peer's address.
    let toml = dynamic_modes_toml(
        "route_reflector_client = true\norr_vantage = \"peer_address\"",
        65001,
    );
    let config = parse(&toml).unwrap();
    let group = &config.peer_groups["modes"];

    for peer in ["10.0.0.42", "10.0.0.77"] {
        let resolved = config
            .resolve_dynamic_neighbor(
                peer.parse().unwrap(),
                65001,
                "dynamic",
                group,
                "modes",
                false,
            )
            .unwrap();
        assert_eq!(
            resolved.transport_config.orr_vantage,
            Some(peer.parse().unwrap()),
            "dynamic peer {peer} resolves the sentinel to its own address"
        );
    }
}

#[test]
fn orr_vantage_peer_address_derives_ipv6_vantages_for_an_ipv6_range() {
    // The derivation is family-agnostic: it collapses to `peer_addr`, which
    // carries whatever family the accepted session used. An IPv6 range must
    // therefore yield IPv6 vantages, which `OrrTopology::resolve_node` looks
    // up via the /128 prefix_v6 LPM arm.
    let toml = format!(
        r#"
{base}

[peer_groups.v6-rr]
route_reflector_client = true
orr_vantage = "peer_address"

[[dynamic_neighbors]]
prefix = "2001:db8::/64"
peer_group = "v6-rr"
remote_asn = 65001
"#,
        base = valid_toml()
    );
    let config = parse(&toml).unwrap();
    let group = &config.peer_groups["v6-rr"];

    for peer in ["2001:db8::42", "2001:db8::77"] {
        let addr: std::net::IpAddr = peer.parse().unwrap();
        let resolved = config
            .resolve_dynamic_neighbor(addr, 65001, "dynamic", group, "v6-rr", false)
            .unwrap();
        assert_eq!(
            resolved.transport_config.orr_vantage,
            Some(addr),
            "IPv6 dynamic peer {peer} resolves the sentinel to its own v6 address"
        );
        assert!(
            resolved.transport_config.orr_vantage.unwrap().is_ipv6(),
            "the derived vantage must stay in the peer's own address family"
        );
    }
}

#[test]
fn orr_vantage_peer_address_resolves_for_a_static_neighbor() {
    // `orr_toml` declares neighbor 10.0.0.2 in AS 65001 (iBGP).
    let toml = orr_toml(
        "",
        "route_reflector_client = true\norr_vantage = \"peer_address\"",
    );
    let config = parse(&toml).unwrap();
    let resolved = config.resolved_neighbors().unwrap();
    assert_eq!(
        resolved[0].transport_config.orr_vantage,
        Some("10.0.0.2".parse().unwrap()),
        "a static neighbor resolves the sentinel to its own peering address"
    );
}

#[test]
fn orr_vantage_peer_address_alias_and_bad_values_are_classified() {
    // The kebab alias loads and resolves identically.
    let toml = orr_toml(
        "",
        "route_reflector_client = true\norr_vantage = \"peer-address\"",
    );
    let resolved = parse(&toml).unwrap().resolved_neighbors().unwrap();
    assert_eq!(
        resolved[0].transport_config.orr_vantage,
        Some("10.0.0.2".parse().unwrap())
    );

    // Garbage fails closed at load with an operator-actionable diagnostic,
    // on the neighbor field and on the peer-group field alike.
    for (neighbor_fields, group_fields) in [
        ("orr_vantage = \"bogus\"", "route_reflector_client = true"),
        ("", "route_reflector_client = true\norr_vantage = \"bogus\""),
    ] {
        let err = parse(&orr_toml(neighbor_fields, group_fields)).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidOrrVantage { .. }),
            "expected InvalidOrrVantage, got {err:?}"
        );
        assert!(
            err.to_string().contains("bogus") && err.to_string().contains("peer_address"),
            "diagnostic names the offending value and the sentinel: {err}"
        );
    }
}

/// `resolve_neighbor` rejects an unparseable vantage instead of panicking.
///
/// Every caller resolves from a validated `Config`, so this is only
/// reachable by mutating the config after load — exactly what a future
/// resolve path that skips `validate()` would do. Pinning the `Err` keeps
/// that mistake a one-neighbor rejection instead of a daemon panic.
#[test]
fn orr_vantage_resolution_rejects_unvalidated_garbage_without_panicking() {
    let toml = orr_toml(
        "",
        "route_reflector_client = true\norr_vantage = \"peer_address\"",
    );
    let mut config = parse(&toml).unwrap();
    config.neighbors[0].orr_vantage = Some("bogus".to_string());

    // `ResolvedNeighbor` is not `Debug`, so match rather than `unwrap_err`.
    let Err(err) = config.resolve_neighbor(&config.neighbors[0].clone()) else {
        panic!("an unparseable vantage must not resolve");
    };
    assert!(
        matches!(err, ConfigError::InvalidOrrVantage { .. }),
        "expected InvalidOrrVantage, got {err:?}"
    );
    assert!(
        err.to_string().contains("10.0.0.2") && err.to_string().contains("bogus"),
        "the error names the neighbor and the offending value: {err}"
    );

    // The inherited group value takes the same path when the neighbor
    // itself carries none.
    config.neighbors[0].orr_vantage = None;
    config.peer_groups.get_mut("clients").unwrap().orr_vantage = Some("bogus".to_string());
    let Err(inherited) = config.resolve_neighbor(&config.neighbors[0].clone()) else {
        panic!("an inherited unparseable vantage must not resolve");
    };
    assert!(
        matches!(inherited, ConfigError::InvalidOrrVantage { .. }),
        "an inherited garbage vantage is rejected the same way, got {inherited:?}"
    );
}

#[test]
fn orr_vantage_peer_address_still_requires_rr_client() {
    // The sentinel is exempt from the address-shape checks, never from the
    // mode checks. (The iBGP half is pinned by the dynamic-range matrix in
    // `dynamic_neighbors.rs`, which drives remote_asn through the range.)
    let err = parse(&orr_toml("", "orr_vantage = \"peer_address\"")).unwrap_err();
    assert!(
        err.to_string()
            .contains("requires route_reflector_client = true"),
        "peer_address without route_reflector_client is rejected: {err}"
    );
}
