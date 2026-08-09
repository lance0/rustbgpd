use super::*;

#[test]
fn transaction_v1_classifies_noop_candidate() {
    let config = parse(valid_toml()).unwrap();
    let diff = diff_config(&config, &config);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_noop());
    assert!(!class.is_committable());
}

#[test]
fn transaction_v1_classifies_supported_runtime_sections() {
    let with_table = |table_id: u32| {
        format!(
            r#"
{}

[peer_groups.ix-members]

[[neighbors]]
address = "10.0.0.99"
remote_asn = 65099

[[fib_tables]]
name = "edge"
table_id = {table_id}
metric = 200

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
            valid_toml()
        )
    };
    let old = parse(&with_table(1000)).unwrap();
    let new_toml = format!(
        r#"
{}

[peer_groups.ix-members]

[[neighbors]]
address = "10.0.0.100"
remote_asn = 65100

[[fib_tables]]
name = "edge"
table_id = 1001
metric = 200

[[dynamic_neighbors]]
prefix = "192.0.3.0/24"
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec![
            "[[neighbors]] add",
            "[[neighbors]] delete",
            "[[dynamic_neighbors]]",
            "[[fib_tables]]",
        ]
    );
    assert_eq!(
        class.unsupported_sections,
        vec!["mixed transaction families"]
    );
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_evpn_runtime_shape_as_unsupported_coordinator() {
    let old = parse(&evpn_toml_with("")).unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(!class.is_committable());
    assert!(class.supported_sections.is_empty(), "{class:?}");
    assert_eq!(class.unsupported_sections, vec!["EVPN runtime coordinator"]);
    assert!(class.restart_required_sections.is_empty(), "{class:?}");
}

#[test]
fn transaction_v1_classifies_static_neighbor_add_delete_as_one_family() {
    let old_toml = format!(
        r#"
{}

[[neighbors]]
address = "10.0.0.99"
remote_asn = 65099
"#,
        valid_toml()
    );
    let new_toml = format!(
        r#"
{}

[[neighbors]]
address = "10.0.0.100"
remote_asn = 65100
"#,
        valid_toml()
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec!["[[neighbors]] add", "[[neighbors]] delete"]
    );
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_rejects_unsupported_reload_sections() {
    let old_toml = format!(
        r#"
{}

[peer_groups.ix-members]
hold_time = 90

[[neighbors]]
address = "10.0.0.101"
remote_asn = 65101
hold_time = 90
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let new_toml = format!(
        r#"
{}

[peer_groups.ix-members]
hold_time = 120

[[neighbors]]
address = "10.0.0.101"
remote_asn = 65101
hold_time = 120
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec![
            "[[neighbors]] modify",
            "[peer_groups] catalog",
            "effective neighbor session reshape",
        ]
    );
    assert!(
        class
            .unsupported_sections
            .contains(&"mixed transaction families".to_string())
    );
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_catalog_only_policy_and_peer_group_changes() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!(
        r#"
{}

[peer_groups.unused]
hold_time = 120

[policy.neighbor_sets.ixp]
addresses = ["10.0.0.2"]

[policy.definitions.prep-only]
default_action = "permit"
"#,
        valid_toml()
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec![
            "[policy] definitions",
            "[policy] neighbor_sets",
            "[peer_groups] catalog",
        ]
    );
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
    assert!(
        diff.effective_neighbor_impact.is_empty(),
        "catalog-only changes must not affect existing neighbors"
    );
}

#[test]
fn transaction_v1_classifies_catalog_only_global_chain_without_neighbors() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

"#;
    let new_toml = format!(
        r#"
{old_toml}

[policy]
import_chain = ["prep-only"]

[policy.definitions.prep-only]
default_action = "permit"
"#
    );
    let old = parse(old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec!["[policy] definitions", "[policy] global chains"]
    );
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_static_neighbor_policy_chain_move_as_live_impact() {
    // A policy-definition edit referenced via a static neighbor's import chain
    // moves that neighbor's resolved import policy with no transport/peer-group
    // reshape — committable by the live-impact executor (re-apply in place).
    let with_policy = |default_action: &str| {
        format!(
            r#"
{}

[policy.definitions.import-filter]
default_action = "{default_action}"
"#,
            valid_toml().replace(
                "hold_time = 90",
                "hold_time = 90\nimport_policy_chain = [\"import-filter\"]",
            )
        )
    };
    let old = parse(&with_policy("permit")).unwrap();
    let new = parse(&with_policy("deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec!["[policy] definitions", "[policy] live impact"]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(class.restart_required_sections.is_empty());
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::PolicyChain
                    && !impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );
    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["reload_applied"]["effective_neighbor_impact"][0]["kind"],
        serde_json::json!("policy_chain")
    );
}

#[test]
fn transaction_v1_rejects_policy_chain_move_with_tcp_ao_key_rotation_as_non_policy_impact() {
    // TCP-AO key material is redacted from Debug, so the live-impact classifier
    // must compare resolved transport config structurally rather than through
    // rendered strings. A key rotation is restart-required transport impact even
    // when the same candidate also moves a policy chain.
    let with_policy_and_tcp_ao = |default_action: &str, key: &str| {
        format!(
            r#"
{}

[policy.definitions.import-filter]
default_action = "{default_action}"
"#,
            valid_toml().replace(
                "hold_time = 90",
                &format!(
                    "hold_time = 90\nimport_policy_chain = [\"import-filter\"]\ntcp_ao = {{ key = \"{key}\", send_id = 1, recv_id = 1, algorithm = \"hmac(sha256)\" }}"
                ),
            )
        )
    };
    let old = parse(&with_policy_and_tcp_ao("permit", "old-secret")).unwrap();
    let new = parse(&with_policy_and_tcp_ao("deny", "new-secret")).unwrap();
    let peer_groups = diff_peer_groups(&old.peer_groups, &new.peer_groups);
    let policy = diff_policy(&old.policy, &new.policy);
    let impact = super::compute_effective_neighbor_impact(&old, &new, &peer_groups, &policy);

    assert!(
        impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{impact:?}"
    );
}

#[test]
fn transaction_v1_classifies_peer_group_field_reshape_with_live_neighbor_impact() {
    // A peer-group hold_time edit reshapes the resolved transport_config of its
    // member neighbor — that needs a session reconfigure, not an in-place chain
    // re-apply, so it routes to the session-reshape executor.
    let with_hold = |hold: u32| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = {hold}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"
"#
        )
    };
    let old = parse(&with_hold(90)).unwrap();
    let new = parse(&with_hold(45)).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec![
            "[peer_groups] catalog",
            "effective neighbor session reshape",
        ]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        class.restart_required_sections.is_empty(),
        "{:?}",
        class.restart_required_sections
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{:?}",
        diff.effective_neighbor_impact
    );
    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["reload_applied"]["effective_neighbor_impact"][0]["kind"],
        serde_json::json!("session_reshape")
    );
}

#[test]
fn transaction_v1_classifies_static_peer_group_reassignment_as_session_reshape() {
    let config = |group: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = 90

[peer_groups.core]
hold_time = 45

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "{group}"
"#
        )
    };
    let old = parse(&config("edge")).unwrap();
    let new = parse(&config("core")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec!["[[neighbors]] modify", "effective neighbor session reshape",]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{:?}",
        diff.effective_neighbor_impact
    );
}

#[test]
fn transaction_v1_rejects_mixed_policy_and_session_reshape_impact() {
    // A candidate that only needs a policy refresh for one peer and a session
    // rebuild for another requires a combined executor. The planner must not
    // route this to the session-reshape executor and silently skip the
    // policy-only peer.
    let config = |hold: u32, action: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.rebuild]
hold_time = {hold}

[policy.definitions.filter]
default_action = "{action}"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rebuild"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
import_policy_chain = ["filter"]
"#
        )
    };
    let old = parse(&config(90, "permit")).unwrap();
    let new = parse(&config(45, "deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable(), "{class:?}");
    assert!(
        class
            .unsupported_sections
            .contains(&"effective neighbor inheritance impact".to_string()),
        "{:?}",
        class.unsupported_sections
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::PolicyChain),
        "{:?}",
        diff.effective_neighbor_impact
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{:?}",
        diff.effective_neighbor_impact
    );
    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["reload_applied"]["effective_neighbor_impact"][0]["kind"],
        serde_json::json!("session_reshape")
    );
}

#[test]
fn transaction_v1_classifies_catalog_policy_change_feeding_dynamic_range_as_live_impact() {
    // A policy-definition edit reaches an established dynamic session through
    // its peer group's chain, even with no static neighbor referencing it.
    // SIGHUP live-reconciles dynamic peers, so the transaction planner must
    // surface the range as live-policy impact rather than treating the edit as
    // catalog-only.
    let config = |action: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
import_policy_chain = ["import-filter"]

[policy.definitions.import-filter]
default_action = "{action}"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config("permit")).unwrap();
    let new = parse(&config("deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec!["[policy] definitions", "[policy] live impact"]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert_eq!(
        diff.effective_neighbor_impact
            .iter()
            .map(|impact| impact.address.clone())
            .collect::<Vec<_>>(),
        vec!["10.30.0.0/16".to_string()],
        "the dynamic range inheriting the changed policy must be flagged"
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::PolicyChain
                    && impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_dynamic_range_peer_group_field_reshape_as_session_reshape() {
    // A dynamic range whose peer-group policy did not move but whose inherited
    // session settings did move is not a dynamic live-policy impact; it routes
    // to the session reshape executor, which gracefully resets the range's
    // live sessions after persist so they re-accept under the committed
    // config.
    let config = |hold: u32| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
hold_time = {hold}

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config(90)).unwrap();
    let new = parse(&config(45)).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec![
            "[peer_groups] catalog",
            "effective neighbor session reshape"
        ]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape
                    && impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );

    // The accepted-hold floor is also inherited session state, so changing it
    // must take the same dynamic reshape path rather than a hot update.
    // Removing it from resolved PeerConfig leaves no floor SessionReshape.
    let with_minimum = |minimum: u32| {
        config(90).replace(
            "hold_time = 90",
            &format!("hold_time = 90\nmin_hold_time = {minimum}"),
        )
    };
    let floor_diff = diff_config(
        &parse(&with_minimum(30)).unwrap(),
        &parse(&with_minimum(45)).unwrap(),
    );
    assert!(floor_diff.effective_neighbor_impact.iter().any(|impact| {
        impact.kind == EffectiveNeighborImpactKind::SessionReshape && impact.is_dynamic_range
    }));
}

#[test]
fn transaction_v1_required_family_edit_reshapes_dynamic_range() {
    // Load-bearing: reverting the config field makes the candidate fail to
    // parse; removing changed-group attribution for dynamic ranges leaves no
    // exact SessionReshape impact for this prefix.
    let config = |required: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[peer_groups.ix]
families = ["ipv4_unicast", "ipv6_unicast"]
required_families = [{required}]
[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config("")).unwrap();
    let new = parse(&config("\"ipv6_unicast\"")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        diff.effective_neighbor_impact
            .iter()
            .map(|impact| (&impact.address, impact.kind, impact.is_dynamic_range))
            .collect::<Vec<_>>(),
        vec![(
            &"10.30.0.0/16".to_string(),
            EffectiveNeighborImpactKind::SessionReshape,
            true,
        )]
    );
}

#[test]
fn transaction_v1_classifies_dynamic_range_combined_transport_and_policy_change_as_session_reshape()
{
    // A peer-group edit that moves BOTH the resolved policy chain AND a
    // transport/session field (hold_time) for a dynamic range is not a pure
    // policy-chain move: the live-impact executor reconfigures policy via a
    // Route Refresh but cannot reconfigure the session transport. It routes to
    // the session reshape executor instead — the post-persist graceful reset
    // covers both deltas, because the re-accepted session resolves its
    // transport AND policy chains from the committed config. It must never be
    // mis-classified as a committable dynamic live-policy move (which would
    // silently drop the reconfigure).
    let config = |hold: u32, action: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
hold_time = {hold}
import_policy_chain = ["filter"]

[policy.definitions.filter]
default_action = "{action}"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config(90, "permit")).unwrap();
    let new = parse(&config(45, "deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert!(
        class
            .supported_sections
            .contains(&"effective neighbor session reshape".to_string()),
        "{:?}",
        class.supported_sections
    );
    assert!(
        !class
            .supported_sections
            .contains(&"[policy] live impact".to_string()),
        "{:?}",
        class.supported_sections
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape
                    && impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );
}

#[test]
fn transaction_v1_rejects_dynamic_range_peer_group_reassignment_as_inheritance_impact() {
    // Reassigning a `[[dynamic_neighbors]]` range to a different peer group is
    // a range-record edit, not a peer-group field reshape: sessions accepted
    // under the old group cannot be live-reassigned, and the record edit
    // belongs to the dynamic-neighbor executor family. The reshape family must
    // not claim it.
    let config = |group: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
hold_time = 90

[peer_groups.transit]
hold_time = 45

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "{group}"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config("ix")).unwrap();
    let new = parse(&config("transit")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable(), "{class:?}");
    assert!(
        class
            .unsupported_sections
            .contains(&"effective neighbor inheritance impact".to_string()),
        "{:?}",
        class.unsupported_sections
    );
    assert!(
        !class
            .supported_sections
            .contains(&"effective neighbor session reshape".to_string()),
        "{:?}",
        class.supported_sections
    );
}

#[test]
fn transaction_v1_classifies_prefix_orf_receive_toggle_as_neighbor_modify() {
    // A bare prefix_orf_receive toggle on an existing neighbor is a
    // [[neighbors]] modify. The transaction surface now commits static neighbor
    // modifies by reconfiguring the peer, so this must be committable — not a
    // no-op (which it silently was while prefix_orf_receive was invisible to
    // the diff).
    let with_orf = |orf: bool| {
        format!(
            r#"
{}

[[neighbors]]
address = "10.0.0.102"
remote_asn = 65102
prefix_orf_receive = {orf}
"#,
            valid_toml()
        )
    };
    let old = parse(&with_orf(false)).unwrap();
    let new = parse(&with_orf(true)).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_noop(), "ORF toggle must not classify as a no-op");
    assert!(class.is_committable());
    assert_eq!(class.supported_sections, vec!["[[neighbors]] modify"]);
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_rejects_restart_required_sections() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable());
    assert!(class.supported_sections.is_empty());
    assert!(
        class
            .restart_required_sections
            .contains(&"[[fib_tables]] startup-from-empty".to_string())
    );
}

#[test]
fn transaction_v1_rejects_dynamic_tcp_ao_add_remove_rotate_and_move() {
    let absent = dynamic_tcp_ao_transaction_config(None, "");
    let original = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "old-secret")), "");
    let rotated = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "new-secret")), "");
    let moved = dynamic_tcp_ao_transaction_config(Some(("192.0.3.0/24", "old-secret")), "");

    for (label, old, new) in [
        ("add", &absent, &original),
        ("remove", &original, &absent),
        ("rotate", &original, &rotated),
        ("move", &original, &moved),
    ] {
        let diff = diff_config(old, new);
        let class = classify_config_transaction_v1(&diff);
        assert!(diff.dynamic_neighbor_tcp_ao_changed, "{label}");
        assert!(!diff.has_reload_applied_changes(), "{label}");
        assert!(!class.is_committable(), "{label}");
        assert!(class.supported_sections.is_empty(), "{label}: {class:?}");
        assert_eq!(
            class.restart_required_sections,
            vec!["[[dynamic_neighbors]].tcp_ao"],
            "{label}"
        );
        let json = config_diff_json_value(&diff);
        assert_eq!(json["reload_applied"]["dynamic_neighbors_changed"], false);
        assert_eq!(
            json["restart_required"]["dynamic_neighbor_tcp_ao_changed"],
            true
        );
    }
}

#[test]
fn transaction_v1_allows_disjoint_unprotected_dynamic_edit_beside_tcp_ao_range() {
    let old = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "secret")), "");
    let new = dynamic_tcp_ao_transaction_config(
        Some(("192.0.2.0/24", "secret")),
        "[[dynamic_neighbors]]\nprefix = \"198.51.100.0/24\"\npeer_group = \"dynamic\"\n",
    );
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.has_reload_applied_changes());
    assert!(class.is_committable(), "{class:?}");
    assert_eq!(class.supported_sections, vec!["[[dynamic_neighbors]]"]);
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn protected_dynamic_range_reorder_is_not_a_tcp_ao_restart_change() {
    let first = dynamic_tcp_ao_transaction_config(
        Some(("192.0.2.0/24", "first-secret")),
        "[[dynamic_neighbors]]\nprefix = \"198.51.100.0/24\"\npeer_group = \"dynamic\"\ntcp_ao = { key = \"second-secret\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }\n",
    );
    let second = dynamic_tcp_ao_transaction_config(
        Some(("198.51.100.0/24", "second-secret")),
        "[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"dynamic\"\ntcp_ao = { key = \"first-secret\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }\n",
    );

    let diff = diff_config(&first, &second);
    let class = classify_config_transaction_v1(&diff);
    assert!(!diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.dynamic_neighbors_reload_applied_changed);
    assert!(class.is_committable(), "{class:?}");
    assert_eq!(class.supported_sections, vec!["[[dynamic_neighbors]]"]);
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn protected_dynamic_range_effective_prefix_identity_avoids_restart_change() {
    let canonical = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "secret")), "");
    let host_bits = dynamic_tcp_ao_transaction_config(Some(("192.0.2.1/24", "secret")), "");

    let diff = diff_config(&canonical, &host_bits);
    assert!(!diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.dynamic_neighbors_reload_applied_changed);
}

#[test]
fn mixed_dynamic_tcp_ao_and_disjoint_unprotected_diff_reports_both_portions() {
    let old = dynamic_tcp_ao_transaction_config(Some(("192.0.2.0/24", "old-secret")), "");
    let new = dynamic_tcp_ao_transaction_config(
        Some(("192.0.2.0/24", "new-secret")),
        "[[dynamic_neighbors]]\nprefix = \"198.51.100.0/24\"\npeer_group = \"dynamic\"\n",
    );
    let diff = diff_config(&old, &new);
    let json = config_diff_json_value(&diff);
    let text = format_config_diff(&diff);

    assert!(diff.dynamic_neighbor_tcp_ao_changed);
    assert!(diff.dynamic_neighbors_reload_applied_changed);
    assert!(diff.has_restart_required_changes());
    assert!(diff.has_reload_applied_changes());
    assert_eq!(
        json["restart_required"]["dynamic_neighbor_tcp_ao_changed"],
        true
    );
    assert_eq!(json["reload_applied"]["dynamic_neighbors_changed"], true);
    assert!(
        text.contains("[[dynamic_neighbors]] matcher rebuilt"),
        "{text}"
    );
    assert!(
        text.contains("[[dynamic_neighbors]].tcp_ao changed"),
        "{text}"
    );

    let class = classify_config_transaction_v1(&diff);
    assert!(!class.is_committable());
    assert!(class.supported_sections.is_empty(), "{class:?}");
    assert_eq!(
        class.restart_required_sections,
        vec!["[[dynamic_neighbors]].tcp_ao"]
    );
}

#[test]
fn full_snapshot_transaction_with_rpol_inputs_is_rejected() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""customer-in(200)""#);
    let current = load_dir(&dir).expect("config with rpol input loads");
    let mut candidate = load_dir(&dir).expect("candidate independently reloads rpol input");
    candidate.neighbors[1].description = Some("changed by transaction".to_string());

    let diff = diff_config(&current, &candidate);
    assert!(!diff.policy.rpol_changed, "external inputs are unchanged");
    let class = classify_config_transaction_v1(&diff);

    assert_eq!(class.supported_sections, vec!["[[neighbors]] modify"]);
    assert_eq!(
        class.unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );
    assert!(!class.is_committable());
}

#[test]
fn rpol_resolution_settings_change_is_unsupported() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""customer-in(200)""#);
    let current = load_dir(&dir).expect("config with rpol input loads");

    let mut roots_candidate = current.clone();
    roots_candidate
        .policy
        .rpol_roots
        .push(dir.path().join("policies").display().to_string());
    let roots_diff = diff_config(&current, &roots_candidate);
    assert!(roots_diff.policy.rpol_changed);
    assert_eq!(
        classify_config_transaction_v1(&roots_diff).unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );

    let mut budget_candidate = current.clone();
    budget_candidate.policy.rpol_max_graph_bytes /= 2;
    let budget_diff = diff_config(&current, &budget_candidate);
    assert!(budget_diff.policy.rpol_changed);
    assert_eq!(
        classify_config_transaction_v1(&budget_diff).unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );
    let json = config_diff_json_value(&budget_diff);
    assert_eq!(json["reload_applied"]["rpol_changed"], true);
    let text = format_config_diff(&budget_diff);
    assert!(text.contains("rpol_max_graph_bytes"), "{text}");
}

#[test]
fn targeted_fib_transaction_with_unchanged_external_inputs_remains_committable() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""customer-in(200)""#);
    let mut current = load_dir(&dir).expect("config with rpol input loads");
    current.fib_tables.push(FibTableConfig {
        name: "edge".to_string(),
        table_id: 1000,
        metric: 200,
        families: vec!["ipv4_unicast".to_string()],
        allowed_peer_groups: Vec::new(),
        allowed_neighbors: Vec::new(),
        max_routes: None,
        maximum_paths: None,
        maximum_paths_ebgp: None,
        maximum_paths_ibgp: None,
    });
    let mut candidate = current.clone();
    candidate.fib_tables[0].metric = 201;

    let diff = diff_config(&current, &candidate);
    let class = classify_config_transaction_v1(&diff);

    assert_eq!(class.supported_sections, vec!["[[fib_tables]]"]);
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(class.is_committable(), "{class:?}");

    let mut budget_candidate = candidate.clone();
    budget_candidate.policy.rpol_max_graph_bytes /= 2;
    let mixed_budget = classify_config_transaction_v1(&diff_config(&current, &budget_candidate));
    assert_eq!(mixed_budget.supported_sections, vec!["[[fib_tables]]"]);
    assert_eq!(
        mixed_budget.unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );
    assert!(!mixed_budget.is_committable());

    let mut roots_candidate = candidate;
    roots_candidate
        .policy
        .rpol_roots
        .push(dir.path().join("policies").display().to_string());
    let mixed_roots = classify_config_transaction_v1(&diff_config(&current, &roots_candidate));
    assert_eq!(mixed_roots.supported_sections, vec!["[[fib_tables]]"]);
    assert_eq!(
        mixed_roots.unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );
    assert!(!mixed_roots.is_committable());
}

#[test]
fn external_input_noop_remains_noop() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""customer-in(200)""#);
    let current = load_dir(&dir).expect("config with rpol input loads");
    let candidate = load_dir(&dir).expect("candidate independently reloads rpol input");

    let diff = diff_config(&current, &candidate);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_noop(), "{class:?}");
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
}
