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
