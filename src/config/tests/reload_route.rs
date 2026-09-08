use super::*;

const RS_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy.definitions.members-in]
default_action = "permit"

[policy.definitions.members-out]
default_action = "permit"

[peer_groups.members]
hold_time = 90
max_prefixes = 1000
import_policy_chain = ["members-in"]
export_policy_chain = ["members-out"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "members"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "members"

[[neighbors]]
address = "2001:db8::4"
remote_asn = 65004
hold_time = 180
"#;

fn rs(toml: &str) -> Config {
    parse(toml).unwrap()
}

fn action(actions: &[ReloadPeerAction], address: &str) -> Option<ReloadPeerActionKind> {
    let key = PeerKey::new(address.parse().unwrap(), None);
    actions
        .iter()
        .find(|action| action.key == key)
        .map(|action| action.kind)
}

#[test]
fn plan_collapses_group_reshape_and_member_edit_into_one_replace() {
    let prior = rs(RS_TOML);
    // Group hold_time is session-bound (reshape) and 10.0.0.2 also edits its
    // own session-bound remote_asn: the legacy path rebuilt 10.0.0.2 twice.
    let candidate = rs(&RS_TOML
        .replace("hold_time = 90", "hold_time = 60")
        .replace("remote_asn = 65002", "remote_asn = 65012"));
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    assert_eq!(
        action(&actions, "10.0.0.2"),
        Some(ReloadPeerActionKind::Replace)
    );
    assert_eq!(
        action(&actions, "10.0.0.3"),
        Some(ReloadPeerActionKind::Replace)
    );
    assert_eq!(
        action(&actions, "2001:db8::4"),
        None,
        "bystander gets no action"
    );
    assert_eq!(
        actions.len(),
        2,
        "exactly one action per touched peer: {actions:?}"
    );
}

#[test]
fn plan_hot_updates_inherited_live_fields_without_reshape() {
    let prior = rs(RS_TOML);
    let candidate = rs(&RS_TOML.replace("max_prefixes = 1000", "max_prefixes = 2000"));
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    assert_eq!(
        action(&actions, "10.0.0.2"),
        Some(ReloadPeerActionKind::HotUpdate)
    );
    assert_eq!(
        action(&actions, "10.0.0.3"),
        Some(ReloadPeerActionKind::HotUpdate)
    );
    assert_eq!(actions.len(), 2);
}

#[test]
fn plan_ignores_per_peer_explain_knobs() {
    let prior = rs(RS_TOML);
    let candidate = rs(&format!(
        "{RS_TOML}\n[policy.explain]\nenabled = true\ncache_size = 64\n"
    ));
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    assert!(
        actions.is_empty(),
        "explain applies on the next session: {actions:?}"
    );
}

#[test]
fn listener_auth_family_ignores_roster_changes_without_authentication() {
    let prior = rs(RS_TOML);
    let added = rs(&format!(
        "{RS_TOML}\n[[neighbors]]\naddress = \"10.0.0.7\"\nremote_asn = 65007\n"
    ));
    let prior_inventory = listener_inbound_auth_inventory(&prior).unwrap();
    let added_inventory = listener_inbound_auth_inventory(&added).unwrap();
    assert_ne!(
        prior_inventory, added_inventory,
        "every neighbor has a selector"
    );
    assert_eq!(
        listener_inbound_auth_bearing(&prior_inventory),
        listener_inbound_auth_bearing(&added_inventory)
    );
    assert!(!diff_config(&prior, &added).listener_inbound_auth_changed);
    let gtsm = rs(&RS_TOML.replace("hold_time = 180", "hold_time = 180\nttl_security = true"));
    assert!(diff_config(&prior, &gtsm).listener_inbound_auth_changed);
}

#[test]
fn plan_gives_policy_only_movement_no_session_action() {
    let prior = rs(RS_TOML);
    let candidate = rs(&RS_TOML.replace(
        "[policy.definitions.members-out]\ndefault_action = \"permit\"",
        "[policy.definitions.members-out]\ndefault_action = \"deny\"",
    ));
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    assert!(actions.is_empty(), "{actions:?}");
}

#[test]
fn plan_adds_removes_and_treats_group_reassignment_as_replace() {
    let prior = rs(RS_TOML);
    let candidate = rs(&RS_TOML
        .replace(
            "[[neighbors]]\naddress = \"10.0.0.3\"\nremote_asn = 65003\npeer_group = \"members\"\n",
            "[[neighbors]]\naddress = \"10.0.0.9\"\nremote_asn = 65009\n",
        )
        .replace(
            "address = \"2001:db8::4\"\nremote_asn = 65004\nhold_time = 180",
            "address = \"2001:db8::4\"\nremote_asn = 65004\npeer_group = \"members\"\nhold_time = 90",
        ));
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    assert_eq!(
        action(&actions, "10.0.0.3"),
        Some(ReloadPeerActionKind::Remove)
    );
    assert_eq!(
        action(&actions, "10.0.0.9"),
        Some(ReloadPeerActionKind::Add)
    );
    assert_eq!(
        action(&actions, "2001:db8::4"),
        Some(ReloadPeerActionKind::Replace),
        "a reassignment is a reshape even when the resolved transport is unchanged"
    );
    assert_eq!(action(&actions, "10.0.0.2"), None);
}

#[test]
fn route_is_sequential_without_generation_class_changes() {
    let families = SighupReloadFamilies {
        fib_tables: true,
        honor_knobs: true,
        ..SighupReloadFamilies::default()
    };
    assert_eq!(
        classify_sighup_reload(families),
        SighupReloadRoute::Sequential {
            reasons: Vec::new()
        }
    );
    assert_eq!(
        classify_sighup_reload(SighupReloadFamilies::default()),
        SighupReloadRoute::Sequential {
            reasons: Vec::new()
        }
    );
}

#[test]
fn route_is_generation_for_pure_generation_class_changes() {
    let families = SighupReloadFamilies {
        generation: true,
        ..SighupReloadFamilies::default()
    };
    assert_eq!(
        classify_sighup_reload(families),
        SighupReloadRoute::Generation
    );
}

#[test]
fn route_rejects_generation_changes_combined_with_uncompensated_families() {
    for (name, families) in [
        (
            "datasets",
            SighupReloadFamilies {
                generation: true,
                datasets: true,
                ..SighupReloadFamilies::default()
            },
        ),
        (
            "dynamic ranges",
            SighupReloadFamilies {
                generation: true,
                dynamic_ranges: true,
                ..SighupReloadFamilies::default()
            },
        ),
        (
            "evpn",
            SighupReloadFamilies {
                generation: true,
                evpn_runtime: true,
                ..SighupReloadFamilies::default()
            },
        ),
        (
            "fib",
            SighupReloadFamilies {
                generation: true,
                fib_tables: true,
                ..SighupReloadFamilies::default()
            },
        ),
        (
            "honor",
            SighupReloadFamilies {
                generation: true,
                honor_knobs: true,
                ..SighupReloadFamilies::default()
            },
        ),
    ] {
        let route = classify_sighup_reload(families);
        assert!(
            matches!(&route, SighupReloadRoute::Rejected { reasons } if reasons.len() == 1),
            "{name}: {route:?}"
        );
    }
    // Every rejected family is named, and rejection wins over the
    // sequential-only families.
    let route = classify_sighup_reload(SighupReloadFamilies {
        generation: true,
        datasets: true,
        fib_tables: true,
        listener_auth: true,
        ..SighupReloadFamilies::default()
    });
    let SighupReloadRoute::Rejected { reasons } = route else {
        panic!("{route:?}");
    };
    assert_eq!(reasons.len(), 2, "{reasons:?}");
}

#[test]
fn route_keeps_listener_auth_and_tcp_ao_on_the_sequential_path() {
    let route = classify_sighup_reload(SighupReloadFamilies {
        generation: true,
        listener_auth: true,
        tcp_ao: true,
        ..SighupReloadFamilies::default()
    });
    let SighupReloadRoute::Sequential { reasons } = route else {
        panic!("{route:?}");
    };
    assert_eq!(reasons.len(), 2, "{reasons:?}");
}

#[test]
fn diff_config_reports_the_sighup_route_and_listener_inventory() {
    let prior = rs(RS_TOML);
    let generation = rs(&RS_TOML.replace("hold_time = 90", "hold_time = 60"));
    let diff = diff_config(&prior, &generation);
    assert!(!diff.listener_inbound_auth_changed);
    assert_eq!(diff.sighup_route, SighupReloadRoute::Generation);
    let text = format_config_diff(&diff);
    assert!(text.contains("SIGHUP reload route: generation"), "{text}");
    let json = config_diff_json_value(&diff);
    assert_eq!(json["sighup_reload"]["route"], "generation");

    let md5 = rs(&RS_TOML.replace(
        "hold_time = 180",
        "hold_time = 180\nmd5_password = \"secret\"",
    ));
    let diff = diff_config(&prior, &md5);
    assert!(diff.listener_inbound_auth_changed);
    assert!(
        matches!(&diff.sighup_route, SighupReloadRoute::Sequential { reasons } if reasons.len() == 1),
        "{:?}",
        diff.sighup_route
    );

    let mixed = rs(&format!(
        "{}\n[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"members\"\nremote_asn = 65100\n",
        RS_TOML.replace("hold_time = 90", "hold_time = 60")
    ));
    let diff = diff_config(&prior, &mixed);
    assert!(
        matches!(&diff.sighup_route, SighupReloadRoute::Rejected { reasons } if reasons == &["[[dynamic_neighbors]]".to_string()]),
        "{:?}",
        diff.sighup_route
    );
    let json = config_diff_json_value(&diff);
    assert_eq!(json["sighup_reload"]["route"], "rejected");
    assert!(
        format_config_diff(&diff)
            .contains("reload these families on their own: [[dynamic_neighbors]]")
    );

    let unchanged = diff_config(&prior, &prior);
    assert!(!format_config_diff(&unchanged).contains("SIGHUP reload route"));
}
