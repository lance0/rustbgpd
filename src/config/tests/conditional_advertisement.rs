//! ADR-0137 conditional-advertisement configuration: schema, validation,
//! diff classification, reload route, persistence, and the resolved install.

use super::*;

const BASE: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy.definitions.backup-routes]
default_action = "deny"

[policy.definitions.transit-a]
default_action = "permit"

[policy.conditional_advertisements.backup]
advertise_policy = "backup-routes"
advertise_if = "absent"
condition_prefixes = ["0.0.0.0/0", "2001:db8::/32"]
condition_policy = "transit-a"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
conditional_advertisements = ["backup"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#;

fn with_definition_line(old: &str, new: &str) -> String {
    assert!(BASE.contains(old), "fixture lacks {old:?}");
    BASE.replacen(old, new, 1)
}

fn policy_error(toml: &str) -> String {
    match parse(toml).unwrap_err() {
        ConfigError::InvalidPolicyEntry { reason } => reason,
        other => panic!("expected InvalidPolicyEntry, got {other:?}"),
    }
}

fn neighbor_error(toml: &str) -> (String, String) {
    match parse(toml).unwrap_err() {
        ConfigError::InvalidNeighborConfig { field, reason, .. } => (field, reason),
        other => panic!("expected InvalidNeighborConfig, got {other:?}"),
    }
}

#[test]
fn definition_and_attachment_load_with_defaults() {
    let config = parse(BASE).unwrap();
    let definition = &config.policy.conditional_advertisements["backup"];
    assert_eq!(definition.advertise_policy, "backup-routes");
    assert_eq!(definition.advertise_if, ConditionalAdvertiseIf::Absent);
    assert_eq!(
        definition.condition_prefixes,
        ["0.0.0.0/0", "2001:db8::/32"]
    );
    assert_eq!(definition.condition_policy.as_deref(), Some("transit-a"));
    assert_eq!(definition.settle_time, 5);
    assert_eq!(config.neighbors[0].conditional_advertisements, ["backup"]);
    assert_eq!(
        config.neighbors[1].conditional_advertisements,
        Vec::<String>::new()
    );

    let present = parse(&with_definition_line(
        "advertise_if = \"absent\"",
        "advertise_if = \"present\"\nsettle_time = 0",
    ))
    .unwrap();
    let definition = &present.policy.conditional_advertisements["backup"];
    assert_eq!(definition.advertise_if, ConditionalAdvertiseIf::Present);
    assert_eq!(definition.settle_time, 0);

    let no_condition_policy = parse(&with_definition_line(
        "condition_policy = \"transit-a\"\n",
        "",
    ))
    .unwrap();
    assert_eq!(
        no_condition_policy.policy.conditional_advertisements["backup"].condition_policy,
        None
    );
}

/// The real load path (startup, `--check`, SIGHUP, config transactions)
/// accepts a valid definition and attachment now that the export gate
/// enforces it.
#[test]
fn valid_conditional_advertisement_loads() {
    let config = Config::load_toml_with_diagnostics(
        &tier_authorized_uds_test_config(BASE),
        "conditional.toml",
    )
    .unwrap();
    assert_eq!(config.neighbors[0].conditional_advertisements, ["backup"]);
}

/// The RIB install carries only attached definitions, keyed by neighbor
/// address, with both predicates compiled and the prefixes parsed.
#[test]
fn resolved_install_carries_attached_definitions_by_address() {
    let unattached = BASE.replacen(
        "[[neighbors]]\naddress = \"10.0.0.2\"",
        "[policy.conditional_advertisements.spare]\nadvertise_policy = \"backup-routes\"\nadvertise_if = \"present\"\ncondition_prefixes = [\"192.0.2.0/24\"]\n\n[[neighbors]]\naddress = \"10.0.0.2\"",
        1,
    );
    let set = parse(&unattached)
        .unwrap()
        .conditional_advertisement_set()
        .unwrap();
    assert_eq!(
        set.definitions.len(),
        1,
        "unattached `spare` is not installed"
    );
    let definition = &set.definitions[0];
    assert_eq!(&*definition.name, "backup");
    assert_eq!(
        definition.advertise_if,
        rustbgpd_rib::ConditionalAdvertiseIf::Absent
    );
    assert_eq!(
        definition
            .condition_prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["0.0.0.0/0", "2001:db8::/32"]
    );
    assert!(definition.condition_policy.is_some());
    assert_eq!(definition.settle_time, std::time::Duration::from_secs(5));
    let attached: Vec<_> = set
        .attachments
        .iter()
        .map(|(peer, names)| {
            (
                peer.to_string(),
                names.iter().map(ToString::to_string).collect::<Vec<_>>(),
            )
        })
        .collect();
    assert_eq!(
        attached,
        [("10.0.0.2".to_string(), vec!["backup".to_string()])]
    );

    // No attachment anywhere: nothing to install.
    let none = BASE.replacen("conditional_advertisements = [\"backup\"]\n", "", 1);
    assert_eq!(
        parse(&none)
            .unwrap()
            .conditional_advertisement_set()
            .unwrap(),
        rustbgpd_rib::ConditionalAdvertisementSet::default()
    );
}

#[test]
fn settle_time_bounds() {
    let at_max = with_definition_line(
        "advertise_if = \"absent\"",
        "advertise_if = \"absent\"\nsettle_time = 600",
    );
    assert_eq!(
        parse(&at_max).unwrap().policy.conditional_advertisements["backup"].settle_time,
        600
    );
    let reason = policy_error(&at_max.replace("settle_time = 600", "settle_time = 601"));
    assert!(
        reason.contains("settle_time = 601 exceeds maximum 600"),
        "{reason}"
    );
}

#[test]
fn undefined_predicate_policies_are_rejected() {
    for (old, new, name) in [
        (
            "advertise_policy = \"backup-routes\"",
            "advertise_policy = \"missing-adv\"",
            "missing-adv",
        ),
        (
            "condition_policy = \"transit-a\"",
            "condition_policy = \"missing-cond\"",
            "missing-cond",
        ),
    ] {
        let error = parse(&with_definition_line(old, new)).unwrap_err();
        assert!(
            matches!(&error, ConfigError::UndefinedPolicy { name: got } if got == name),
            "{error:?}"
        );
    }
}

#[test]
fn condition_prefix_errors_are_rejected() {
    for (prefixes, expected) in [
        ("[]", "condition_prefixes must not be empty"),
        ("[\"10.0.0.0\"]", "is not in CIDR notation"),
        ("[\"10.0.0.300/24\"]", "has an invalid address"),
        ("[\"10.0.0.0/x\"]", "has an invalid length"),
        ("[\"10.0.0.0/33\"]", "length exceeds 32"),
        ("[\"2001:db8::/129\"]", "length exceeds 128"),
        ("[\"10.0.0.1/24\"]", "has host bits set; use 10.0.0.0/24"),
        (
            "[\"2001:db8::1/32\"]",
            "has host bits set; use 2001:db8::/32",
        ),
        (
            "[\"192.0.2.0/24\", \"192.0.2.0/24\"]",
            "is listed more than once",
        ),
    ] {
        let toml = with_definition_line(
            "condition_prefixes = [\"0.0.0.0/0\", \"2001:db8::/32\"]",
            &format!("condition_prefixes = {prefixes}"),
        );
        let reason = policy_error(&toml);
        assert!(
            reason.starts_with("conditional advertisement \"backup\": ")
                && reason.contains(expected),
            "{prefixes}: {reason}"
        );
    }
}

#[test]
fn empty_definition_name_is_rejected() {
    let reason = policy_error(&with_definition_line(
        "[policy.conditional_advertisements.backup]",
        "[policy.conditional_advertisements.\" \"]",
    ));
    assert!(reason.contains("name must not be empty"), "{reason}");
}

#[test]
fn neighbor_attachment_errors_are_rejected() {
    let (field, reason) = neighbor_error(&with_definition_line(
        "conditional_advertisements = [\"backup\"]",
        "conditional_advertisements = [\"missing\"]",
    ));
    assert_eq!(field, "conditional_advertisements");
    assert!(
        reason.contains("undefined conditional advertisement \"missing\""),
        "{reason}"
    );

    let (field, reason) = neighbor_error(&with_definition_line(
        "conditional_advertisements = [\"backup\"]",
        "conditional_advertisements = [\"backup\", \"backup\"]",
    ));
    assert_eq!(field, "conditional_advertisements");
    assert!(reason.contains("attached more than once"), "{reason}");
}

#[test]
fn schema_rejects_unknown_fields_values_and_dynamic_owners() {
    for (label, toml) in [
        (
            "advertise_if value",
            with_definition_line("advertise_if = \"absent\"", "advertise_if = \"sometimes\""),
        ),
        (
            "missing advertise_if",
            with_definition_line("advertise_if = \"absent\"\n", ""),
        ),
        (
            "unknown definition field",
            with_definition_line(
                "advertise_if = \"absent\"",
                "advertise_if = \"absent\"\nexist_map = \"x\"",
            ),
        ),
        (
            "dynamic-neighbor attachment",
            format!(
                "{BASE}\n[peer_groups.edge]\nhold_time = 90\n\n[[dynamic_neighbors]]\n\
                 prefix = \"10.1.0.0/24\"\npeer_group = \"edge\"\n\
                 conditional_advertisements = [\"backup\"]\n"
            ),
        ),
    ] {
        assert!(
            matches!(parse(&toml), Err(ConfigError::Parse(_))),
            "{label} must be a schema error"
        );
    }
}

#[test]
fn attachment_change_is_a_hot_applied_generation_change() {
    let prior = parse(BASE).unwrap();
    let candidate = parse(&BASE.replacen(
        "remote_asn = 65003\n",
        "remote_asn = 65003\nconditional_advertisements = [\"backup\"]\n",
        1,
    ))
    .unwrap();

    let diff = diff_config(&prior, &candidate);
    assert_eq!(diff.neighbors.changed.len(), 1);
    assert_eq!(diff.neighbors.changed[0].address, "10.0.0.3");
    let old = &prior.neighbors[1];
    let new = &candidate.neighbors[1];
    let changes = describe_neighbor_changes(old, new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].field, "conditional_advertisements");
    assert_eq!(changes[0].impact, Some(ConfigFieldImpact::HotApplied));
    assert!(neighbor_change_hot_applicable(old, new));
    assert_eq!(diff.sighup_route, SighupReloadRoute::Generation);
    assert_eq!(
        diff.policy.conditional_advertisements_changed,
        Vec::<String>::new()
    );
}

#[test]
fn definition_change_is_a_reported_generation_change() {
    let prior = parse(BASE).unwrap();
    let candidate = parse(&with_definition_line(
        "advertise_if = \"absent\"",
        "advertise_if = \"absent\"\nsettle_time = 30",
    ))
    .unwrap();

    let diff = diff_config(&prior, &candidate);
    assert_eq!(diff.policy.conditional_advertisements_changed, ["backup"]);
    assert!(diff.policy.has_changes());
    assert!(diff.has_reload_applied_changes());
    assert!(diff.neighbors.changed.is_empty());
    assert_eq!(diff.sighup_route, SighupReloadRoute::Generation);
    assert!(
        format_config_diff(&diff).contains("conditional_advertisement \"backup\""),
        "{}",
        format_config_diff(&diff)
    );
    assert_eq!(
        config_diff_json_value(&diff)["reload_applied"]["conditional_advertisements_changed"],
        serde_json::json!(["backup"])
    );
    let class = classify_config_transaction_v1(&diff);
    assert_eq!(
        class.supported_sections,
        [TRANSACTION_POLICY_DEFINITIONS_SECTION]
    );
    assert_eq!(class.unsupported_sections, Vec::<String>::new());

    // Added and removed definitions are reported the same way, sorted.
    let mut added = candidate.clone();
    added.policy.conditional_advertisements.insert(
        "alpha".to_string(),
        added.policy.conditional_advertisements["backup"].clone(),
    );
    added.policy.conditional_advertisements.remove("backup");
    added.neighbors[0].conditional_advertisements = vec!["alpha".to_string()];
    let diff = diff_config(&prior, &added);
    assert_eq!(
        diff.policy.conditional_advertisements_changed,
        ["alpha", "backup"]
    );
}

/// Only the generation route commits definitions and attachments, so a
/// sequential-route candidate that also changes either is rejected, naming
/// what changed. The same change alone stays on the generation route.
#[test]
fn sequential_route_rejects_conditional_advertisement_changes() {
    let md5 = |toml: &str| {
        toml.replacen(
            "remote_asn = 65003\n",
            "remote_asn = 65003\nmd5_password = \"secret\"\n",
            1,
        )
    };
    let prior = parse(BASE).unwrap();
    assert!(matches!(
        diff_config(&prior, &parse(&md5(BASE)).unwrap()).sighup_route,
        SighupReloadRoute::Sequential { .. }
    ));

    let definition = with_definition_line(
        "advertise_if = \"absent\"",
        "advertise_if = \"absent\"\nsettle_time = 30",
    );
    let attachment = BASE.replacen("conditional_advertisements = [\"backup\"]\n", "", 1);
    for (candidate, expected) in [
        (
            &definition,
            "conditional advertisement \"backup\" changed together with ",
        ),
        (
            &attachment,
            "neighbor 10.0.0.2 conditional_advertisements changed together with ",
        ),
    ] {
        assert_eq!(
            diff_config(&prior, &parse(candidate).unwrap()).sighup_route,
            SighupReloadRoute::Generation
        );
        let SighupReloadRoute::Rejected { reasons } =
            diff_config(&prior, &parse(&md5(candidate)).unwrap()).sighup_route
        else {
            panic!("sequential candidate with {expected:?} must be rejected");
        };
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].starts_with(expected), "{reasons:?}");
    }

    // Removing a neighbor removes its attachments with it: nothing is left
    // for the route to commit, so the removal keeps the sequential route.
    let removed = BASE.replacen(
        "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n\
         conditional_advertisements = [\"backup\"]\n",
        "",
        1,
    );
    assert_ne!(removed, BASE);
    assert!(matches!(
        diff_config(&prior, &parse(&md5(&removed)).unwrap()).sighup_route,
        SighupReloadRoute::Sequential { .. }
    ));
}

#[test]
fn persistence_round_trips_sorted_and_omits_when_unused() {
    let config = parse(BASE).unwrap();
    let document = persisted_config_document(&config).unwrap();
    let reloaded: Config = toml::from_str(&document).unwrap();
    assert_eq!(
        reloaded.policy.conditional_advertisements,
        config.policy.conditional_advertisements
    );
    assert_eq!(reloaded.neighbors[0].conditional_advertisements, ["backup"]);
    assert_eq!(persisted_config_document(&reloaded).unwrap(), document);

    // Definitions persist in name order regardless of insertion order.
    let definition = config.policy.conditional_advertisements["backup"].clone();
    let ordered = |names: &[&str]| {
        let mut config = config.clone();
        config.policy.conditional_advertisements.clear();
        for name in names {
            config
                .policy
                .conditional_advertisements
                .insert((*name).to_string(), definition.clone());
        }
        persisted_config_document(&config).unwrap()
    };
    let names = ["zeta", "alpha", "mid", "beta", "omega", "gamma"];
    let mut reversed = names;
    reversed.reverse();
    assert_eq!(ordered(&names), ordered(&reversed));

    // Unused: neither the table nor the empty attachment list is written.
    let plain = parse(valid_toml()).unwrap();
    let document = persisted_config_document(&plain).unwrap();
    assert!(
        !document.contains("conditional_advertisements"),
        "{document}"
    );
}

/// `BASE` with peer group `edge` carrying `group_list`, neighbor 10.0.0.3 in
/// it with no list of its own, and neighbor 10.0.0.2 in it with its own
/// `["backup"]`, plus a second definition `core`.
fn grouped(group_list: &str) -> String {
    BASE.replacen(
        "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n",
        &format!(
            "[policy.conditional_advertisements.core]\nadvertise_policy = \"backup-routes\"\n\
             advertise_if = \"present\"\ncondition_prefixes = [\"192.0.2.0/24\"]\n\n\
             [peer_groups.edge]\nhold_time = 90\n{group_list}\n\
             [[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\npeer_group = \"edge\"\n"
        ),
        1,
    )
    .replacen(
        "address = \"10.0.0.3\"\nremote_asn = 65003\n",
        "address = \"10.0.0.3\"\nremote_asn = 65003\npeer_group = \"edge\"\n",
        1,
    )
}

fn attachments(config: &Config) -> Vec<(String, Vec<String>)> {
    config
        .conditional_advertisement_set()
        .unwrap()
        .attachments
        .into_iter()
        .map(|(peer, names)| {
            (
                peer.to_string(),
                names.iter().map(ToString::to_string).collect(),
            )
        })
        .collect()
}

/// A member with no list of its own inherits the group's; a member's own
/// non-empty list replaces it (the `export_policy_chain` rule). Only
/// attached definitions are installed.
#[test]
fn peer_group_attachment_is_inherited_unless_the_neighbor_sets_its_own() {
    let config = parse(&grouped("conditional_advertisements = [\"core\"]\n")).unwrap();
    assert_eq!(
        attachments(&config),
        [
            ("10.0.0.2".to_string(), vec!["backup".to_string()]),
            ("10.0.0.3".to_string(), vec!["core".to_string()]),
        ]
    );
    let set = config.conditional_advertisement_set().unwrap();
    let mut names: Vec<_> = set.definitions.iter().map(|d| d.name.to_string()).collect();
    names.sort();
    assert_eq!(names, ["backup", "core"]);

    let detached = parse(&grouped("")).unwrap();
    assert_eq!(
        attachments(&detached),
        [("10.0.0.2".to_string(), vec!["backup".to_string()])]
    );
}

#[test]
fn peer_group_attachment_errors_are_rejected() {
    for (list, expected) in [
        (
            "conditional_advertisements = [\"missing\"]\n",
            "undefined conditional advertisement \"missing\"",
        ),
        (
            "conditional_advertisements = [\"core\", \"core\"]\n",
            "attached more than once",
        ),
    ] {
        match parse(&grouped(list)).unwrap_err() {
            ConfigError::InvalidNeighborConfig {
                address,
                field,
                reason,
            } => {
                assert_eq!(address, "peer_group.edge");
                assert_eq!(field, "conditional_advertisements");
                assert!(reason.contains(expected), "{reason}");
            }
            other => panic!("expected InvalidNeighborConfig, got {other:?}"),
        }
    }
}

/// Attaching, changing, and detaching at the group is a hot-applied group
/// change on the generation route that moves no session, and a sequential
/// candidate carrying it is rejected, naming the group field and the
/// inheriting neighbor.
#[test]
fn peer_group_attachment_changes_reload_on_the_generation_route() {
    let md5 = |toml: &str| {
        toml.replacen(
            "remote_asn = 65003\n",
            "remote_asn = 65003\nmd5_password = \"secret\"\n",
            1,
        )
    };
    let none = grouped("");
    let backup = grouped("conditional_advertisements = [\"backup\"]\n");
    let core = grouped("conditional_advertisements = [\"core\"]\n");
    for (label, prior_toml, candidate_toml) in [
        ("attach", &none, &backup),
        ("change", &backup, &core),
        ("detach", &core, &none),
    ] {
        let prior = parse(prior_toml).unwrap();
        let candidate = parse(candidate_toml).unwrap();
        let diff = diff_config(&prior, &candidate);
        assert_eq!(diff.peer_groups.changed, ["edge"], "{label}");
        assert!(diff.neighbors.changed.is_empty(), "{label}");
        let changes =
            describe_peer_group_changes(&prior.peer_groups["edge"], &candidate.peer_groups["edge"]);
        assert_eq!(changes.len(), 1, "{label}");
        assert_eq!(changes[0].field, "conditional_advertisements", "{label}");
        assert_eq!(
            changes[0].impact,
            Some(ConfigFieldImpact::HotApplied),
            "{label}"
        );
        assert_eq!(diff.sighup_route, SighupReloadRoute::Generation, "{label}");
        assert!(
            plan_reload_peer_actions(&prior, &candidate)
                .unwrap()
                .is_empty(),
            "{label}: no session action"
        );
        assert_ne!(attachments(&prior), attachments(&candidate), "{label}");

        let sequential = parse(&md5(candidate_toml)).unwrap();
        let SighupReloadRoute::Rejected { reasons } = diff_config(&prior, &sequential).sighup_route
        else {
            panic!("{label}: a sequential candidate must be rejected");
        };
        assert!(
            reasons
                .iter()
                .any(|reason| reason.starts_with("peer group \"edge\" conditional_advertisements")),
            "{label}: {reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.starts_with("neighbor 10.0.0.3 conditional_advertisements")),
            "{label}: {reasons:?}"
        );
    }
}
