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

/// A route-server member joining or leaving with its own MD5 password or
/// GTSM selector, together with its datasets, is one generation: the listener
/// entries belong to a whole neighbor the generation adds or removes. Editing
/// an existing neighbor's password or GTSM setting alongside datasets still
/// rejects.
#[test]
fn authenticated_member_join_and_leave_with_datasets_take_the_generation_route() {
    let dir = dataset_config_dir("64500\n");
    let bound = load_dir(&dir).unwrap();
    let with_datasets = |toml: &str| {
        let mut config = rs(toml);
        config.policy.datasets = bound.policy.datasets.clone();
        config.policy.dataset_bindings = bound.policy.dataset_bindings.clone();
        config
    };
    let prior = rs(RS_TOML);
    let member = |auth: &str| {
        format!("{RS_TOML}\n[[neighbors]]\naddress = \"10.0.0.7\"\nremote_asn = 65007\n{auth}\n")
    };
    let rejected = SighupReloadRoute::Rejected {
        reasons: vec!["dataset changes with listener MD5/GTSM changes".to_string()],
    };

    for auth in ["md5_password = \"member-secret\"", "ttl_security = true"] {
        let join = diff_config(&prior, &with_datasets(&member(auth)));
        assert!(join.policy.datasets_changed, "{auth}");
        assert!(!join.listener_inbound_auth_changed, "join {auth}");
        assert_eq!(
            join.sighup_route,
            SighupReloadRoute::Generation,
            "join {auth}"
        );

        let leave = diff_config(&with_datasets(&member(auth)), &prior);
        assert!(!leave.listener_inbound_auth_changed, "leave {auth}");
        assert_eq!(
            leave.sighup_route,
            SighupReloadRoute::Generation,
            "leave {auth}"
        );

        // The same authentication applied to an existing neighbor is an
        // in-place edit, alone or next to a whole-member join.
        let edit_toml = RS_TOML.replace("hold_time = 180", &format!("hold_time = 180\n{auth}"));
        let edit = diff_config(&prior, &with_datasets(&edit_toml));
        assert!(edit.listener_inbound_auth_changed, "edit {auth}");
        assert_eq!(edit.sighup_route, rejected, "edit {auth}");
        let edit_and_join = format!(
            "{edit_toml}\n[[neighbors]]\naddress = \"10.0.0.7\"\nremote_asn = 65007\n{auth}\n"
        );
        assert_eq!(
            diff_config(&prior, &with_datasets(&edit_and_join)).sighup_route,
            rejected,
            "edit and join {auth}"
        );
    }

    // A changed password or hop count on a member present on both sides.
    let md5_member = member("md5_password = \"member-secret\"");
    let rotated = md5_member.replace("member-secret", "rotated-secret");
    assert_eq!(
        diff_config(&rs(&md5_member), &with_datasets(&rotated)).sighup_route,
        rejected
    );
    let gtsm_member = member("ttl_security = true");
    let hops = gtsm_member.replace(
        "ttl_security = true",
        "ttl_security = true\nttl_security_hops = 2",
    );
    assert_eq!(
        diff_config(&rs(&gtsm_member), &with_datasets(&hops)).sighup_route,
        rejected
    );
    // A peer-group password reaches its existing members in place.
    let group_md5 = RS_TOML.replace(
        "max_prefixes = 1000",
        "max_prefixes = 1000\nmd5_password = \"group-secret\"",
    );
    assert_eq!(
        diff_config(&prior, &with_datasets(&group_md5)).sighup_route,
        rejected
    );
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
        dataset_bindings: true,
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
fn route_compensates_dataset_content_and_bindings_and_rejects_auth_combinations() {
    for generation in [false, true] {
        for (datasets, dataset_bindings) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                classify_sighup_reload(SighupReloadFamilies {
                    generation,
                    datasets,
                    dataset_bindings,
                    ..SighupReloadFamilies::default()
                }),
                SighupReloadRoute::Generation,
                "generation={generation} datasets={datasets} bindings={dataset_bindings}"
            );
            for (tcp_ao, listener_auth) in [(true, false), (false, true)] {
                assert!(
                    matches!(
                        classify_sighup_reload(SighupReloadFamilies {
                            generation,
                            datasets,
                            dataset_bindings,
                            tcp_ao,
                            listener_auth,
                            ..SighupReloadFamilies::default()
                        }),
                        SighupReloadRoute::Rejected { .. }
                    ),
                    "generation={generation} datasets={datasets} bindings={dataset_bindings} tcp_ao={tcp_ao} listener_auth={listener_auth}"
                );
            }
        }
    }
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

    let dir = dataset_config_dir("64500\n");
    let bound = load_dir(&dir).unwrap();
    let mut unbound = bound.clone();
    unbound.policy.datasets.clear();
    unbound.policy.dataset_bindings = rustbgpd_policy::datasets::DatasetBindings::new();
    let diff = diff_config(&unbound, &bound);
    assert!(diff.policy.datasets_changed);
    assert_eq!(
        diff.sighup_route,
        SighupReloadRoute::Generation,
        "a binding change reports the generation route"
    );
    assert_eq!(
        config_diff_json_value(&diff)["sighup_reload"]["route"],
        "generation"
    );

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

#[test]
fn bfd_member_reload_rejects_in_place_authentication_but_keeps_owned_generation() {
    for (tcp_ao, listener_auth) in [(true, false), (false, true), (true, true)] {
        let route = classify_sighup_reload(SighupReloadFamilies {
            generation: true,
            bfd_members: true,
            tcp_ao,
            listener_auth,
            ..SighupReloadFamilies::default()
        });
        let SighupReloadRoute::Rejected { reasons } = &route else {
            panic!("BFD must not bypass generation acknowledgement: {route:?}");
        };
        assert!(
            reasons
                .iter()
                .all(|reason| reason.contains("BFD member changes"))
        );
        assert!(
            route
                .describe()
                .contains("reload these families on their own")
        );
    }
    assert_eq!(
        classify_sighup_reload(SighupReloadFamilies {
            bfd_members: true,
            ..SighupReloadFamilies::default()
        }),
        SighupReloadRoute::Generation
    );
}

#[test]
fn bfd_auth_compound_diff_reports_rejection_in_json_and_human_output() {
    let prior = rs(&format!("{RS_TOML}\n[[bfd_profiles]]\nname = \"fast\"\n"));
    let mut candidate = prior.clone();
    candidate.neighbors[0].md5_password = Some("secret".to_string());
    candidate.neighbors[0].bfd = Some(BfdConfig {
        profile: "fast".to_string(),
        enabled: true,
        strict: false,
        multihop: false,
    });
    let diff = diff_config(&prior, &candidate);
    assert!(diff.bfd_members_changed);
    assert_eq!(
        config_diff_json_value(&diff)["sighup_reload"]["route"],
        "rejected"
    );
    let text = format_config_diff(&diff);
    assert!(
        text.contains("reload these families on their own"),
        "{text}"
    );
    assert!(
        text.contains("BFD member changes with listener MD5/GTSM changes"),
        "{text}"
    );
}
