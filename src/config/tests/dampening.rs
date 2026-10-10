//! Disabled-only dampening schema, inheritance, validation and persistence.

use super::*;

const GLOBAL: &str = "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[global.telemetry]\nlog_format = \"json\"\n";
const PEER: &str = "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n";

fn config(parameters: &str, peer: &str) -> String {
    format!("{GLOBAL}\n[policy.route_flap_dampening]\n{parameters}\n{peer}")
}

#[test]
fn dampening_defaults_round_trip_and_omission_preserves_old_shape() {
    let absent = parse(&format!("{GLOBAL}\n{PEER}")).unwrap();
    assert!(absent.policy.route_flap_dampening.is_none());
    assert!(
        !persisted_config_document(&absent)
            .unwrap()
            .contains("route_flap_dampening")
    );
    let present = parse(&config(
        "",
        &format!("{PEER}route_flap_dampening = false\n"),
    ))
    .unwrap();
    let parameters = present.policy.route_flap_dampening.as_ref().unwrap();
    assert_eq!(*parameters, RouteFlapDampeningConfig::default());
    let document = persisted_config_document(&present).unwrap();
    let reloaded: Config = toml::from_str(&document).unwrap();
    reloaded.validate().unwrap();
    assert_eq!(
        reloaded.policy.route_flap_dampening,
        present.policy.route_flap_dampening
    );
    assert_eq!(reloaded.neighbors[0].route_flap_dampening, Some(false));
    assert!(
        !diff_config(&present, &reloaded)
            .policy
            .route_flap_dampening_changed
    );
    let identical = parse(&config(
        "",
        &format!("{PEER}route_flap_dampening = false\n"),
    ))
    .unwrap();
    assert!(!diff_config(&present, &identical).has_any_changes());
}

#[test]
fn invalid_dampening_parameters_name_the_field() {
    for (parameters, field) in [
        ("half_life = 59", "half_life"),
        ("reuse = 0", "reuse"),
        ("suppress = 750", "suppress"),
        ("suppress = 50001", "suppress"),
        ("max_suppress_time = 899", "max_suppress_time"),
        (
            "half_life = 60\nmax_suppress_time = 14400",
            "max_suppress_time",
        ),
        ("suppress = 12001", "suppress"),
    ] {
        let ConfigError::InvalidPolicyEntry { reason } =
            parse(&config(parameters, PEER)).unwrap_err()
        else {
            panic!("expected a policy error for {parameters}");
        };
        assert!(
            reason.contains(&format!("policy.route_flap_dampening.{field}")),
            "{reason}"
        );
    }
    assert!(parse(&config("mode = \"unknown\"", PEER)).is_err());
    assert!(parse(&config("typo = true", PEER)).is_err());
    assert!(parse(&config("suppress = 50000\nmax_suppress_time = 6300", PEER)).is_ok());
}

#[test]
fn effective_enablement_is_refused_in_both_modes_and_all_sources() {
    for mode in ["suppress", "observe"] {
        for (parameters, peer) in [
            (
                format!("mode = \"{mode}\"\napply_to_ebgp = true"),
                PEER.to_string(),
            ),
            (
                format!("mode = \"{mode}\""),
                format!("{PEER}route_flap_dampening = true\n"),
            ),
            (
                format!("mode = \"{mode}\""),
                format!(
                    "[peer_groups.edge]\nroute_flap_dampening = true\n\n{PEER}peer_group = \"edge\"\n"
                ),
            ),
        ] {
            let ConfigError::InvalidNeighborConfig { field, reason, .. } =
                parse(&config(&parameters, &peer)).unwrap_err()
            else {
                panic!("expected a neighbor enablement error");
            };
            assert_eq!(field, "route_flap_dampening");
            assert!(reason.contains("runtime integration is not implemented"));
        }
    }
    let dynamic = "[peer_groups.edge]\nroute_flap_dampening = true\n\n[[dynamic_neighbors]]\nprefix = \"10.1.0.0/24\"\npeer_group = \"edge\"\nremote_asn = 0\n";
    let ConfigError::InvalidDynamicNeighbor { reason } = parse(&config("", dynamic)).unwrap_err()
    else {
        panic!("expected a dynamic enablement error");
    };
    assert!(reason.contains("route_flap_dampening"));
    assert!(reason.contains("runtime integration is not implemented"));
}

#[test]
fn explicit_role_refusals_and_inherited_exclusions_follow_the_contract() {
    for (peer, expected) in [
        (
            format!(
                "{}route_flap_dampening = true\n",
                PEER.replace("65002", "65001")
            ),
            "iBGP",
        ),
        (
            format!("{PEER}route_server_client = true\nroute_flap_dampening = true\n"),
            "route-server client",
        ),
    ] {
        let ConfigError::InvalidNeighborConfig { field, reason, .. } =
            parse(&config("", &peer)).unwrap_err()
        else {
            panic!("expected a role refusal");
        };
        assert_eq!(field, "route_flap_dampening");
        assert!(reason.contains(expected), "{reason}");
    }
    for peer in [
        format!("{}peer_group = \"edge\"\n", PEER.replace("65002", "65001")),
        format!("{PEER}route_server_client = true\npeer_group = \"edge\"\n"),
        format!("{PEER}peer_group = \"edge\"\nroute_flap_dampening = false\n"),
    ] {
        let grouped = format!("[peer_groups.edge]\nroute_flap_dampening = true\n\n{peer}");
        assert!(parse(&config("apply_to_ebgp = true", &grouped)).is_ok());
    }
    let global_override = format!("{PEER}route_flap_dampening = false\n");
    assert!(parse(&config("apply_to_ebgp = true", &global_override)).is_ok());
}

#[test]
fn disabled_schema_edits_are_visible_and_require_generation_snapshot_adoption() {
    let old = parse(&format!("{GLOBAL}\n{PEER}")).unwrap();
    let new = parse(&config("", PEER)).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.policy.route_flap_dampening_changed);
    assert!(diff.has_any_changes());
    assert!(format_config_diff(&diff).contains("route_flap_dampening (disabled-only schema)"));
    assert_eq!(
        config_diff_json_value(&diff)["reload_applied"]["route_flap_dampening_changed"],
        true
    );
    assert_eq!(
        classify_sighup_reload(SighupReloadFamilies::from_diff(&diff)),
        SighupReloadRoute::Generation
    );
    let sequential = SighupReloadRoute::Sequential {
        reasons: vec!["listener inbound MD5/GTSM inventory".into()],
    };
    assert!(matches!(
        reject_unappliable_sequential_reload(sequential, &old, &new),
        SighupReloadRoute::Rejected { .. }
    ));

    let mut changed = new.clone();
    changed.neighbors[0].route_flap_dampening = Some(false);
    assert_eq!(
        describe_neighbor_changes(&new.neighbors[0], &changed.neighbors[0])[0].field,
        "route_flap_dampening"
    );
    assert!(!neighbor_runtime_equal(
        &new.neighbors[0],
        &changed.neighbors[0]
    ));
    let source = PeerGroupConfig {
        route_flap_dampening: Some(false),
        ..PeerGroupConfig::default()
    };
    let mut target = PeerGroupConfig::default();
    copy_peer_group_file_only_fields(&mut target, &source);
    assert_eq!(target.route_flap_dampening, Some(false));
    assert_eq!(
        peer_group_file_only_differences(&source, &PeerGroupConfig::default()),
        ["route_flap_dampening"]
    );
}
