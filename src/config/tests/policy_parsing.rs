use super::*;

#[test]
fn policy_config_parsed() {
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

[policy]
import_chain = ["import-filter"]
export_chain = ["export-filter"]

[policy.definitions.import-filter]
[[policy.definitions.import-filter.statements]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 24
le = 32

[policy.definitions.export-filter]
[[policy.definitions.export-filter.statements]]
action = "permit"
prefix = "192.168.0.0/16"
"#;
    let config = parse(toml_str).unwrap();
    let import = config.import_chain().unwrap().unwrap();
    assert_eq!(import.policies[0].entries.len(), 1);
    let export = config.export_chain().unwrap().unwrap();
    assert_eq!(export.policies[0].entries.len(), 1);
}

#[test]
fn empty_policy_returns_none() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.import_chain().unwrap().is_none());
    assert!(config.export_chain().unwrap().is_none());
}

#[test]
fn multiple_neighbors() {
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
description = "peer-a"
hold_time = 90

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
hold_time = 180
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].1, "peer-a");
    assert_eq!(peers[1].1, "10.0.0.3"); // no description → address used
}

#[test]
fn per_neighbor_policy_parsed() {
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

[[neighbors.import_policy]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors.export_policy]]
action = "permit"
prefix = "192.168.0.0/16"
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].import_policy.len(), 1);
    assert_eq!(config.neighbors[0].export_policy.len(), 1);

    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].2.is_some()); // import policy
    assert!(peers[0].3.is_some()); // export policy
}

#[test]
fn per_neighbor_without_policy_falls_back_to_global() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
export_chain = ["deny-tens"]

[policy.definitions.deny-tens]
[[policy.definitions.deny-tens.statements]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
    let config = parse(toml_str).unwrap();
    assert!(config.neighbors[0].import_policy.is_empty());
    assert!(config.neighbors[0].export_policy.is_empty());

    let peers = config.to_peer_configs().unwrap();
    // Should inherit global export policy
    assert!(peers[0].2.is_none()); // no import (neither neighbor nor global)
    assert!(peers[0].3.is_some()); // export from global
}

#[test]
fn per_neighbor_policy_overrides_global() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
export_chain = ["deny-tens"]

[policy.definitions.deny-tens]
[[policy.definitions.deny-tens.statements]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors.export_policy]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();

    // First neighbor: has per-neighbor export → uses that
    let export1 = peers[0].3.as_ref().unwrap();
    assert_eq!(export1.policies[0].entries[0].action, PolicyAction::Permit);

    // Second neighbor: no per-neighbor → falls back to global deny
    let export2 = peers[1].3.as_ref().unwrap();
    assert_eq!(export2.policies[0].entries[0].action, PolicyAction::Deny);
}

#[test]
fn invalid_policy_action_rejected() {
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
action = "allow"
prefix = "10.0.0.0/8"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn invalid_policy_prefix_rejected() {
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

[policy.definitions.t]
[[policy.definitions.t.statements]]
action = "deny"
prefix = "not-a-prefix"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_prefix_length_over_32_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy.definitions.t]
[[policy.definitions.t.statements]]
action = "deny"
prefix = "10.0.0.0/33"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_ge_over_32_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy.definitions.t]
[[policy.definitions.t.statements]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 33
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_ge_less_than_prefix_len_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy.definitions.t]
[[policy.definitions.t.statements]]
action = "deny"
prefix = "10.0.0.0/16"
ge = 8
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_ge_exceeds_le_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy.definitions.t]
[[policy.definitions.t.statements]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 24
le = 16
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_aspath_length_ge_exceeds_le_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy.definitions.t]
[[policy.definitions.t.statements]]
action = "deny"
match_as_path_length_ge = 50
match_as_path_length_le = 10
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn community_only_entry_parses() {
    let toml = community_toml(
        r#"action = "deny"
            match_community = ["RT:65001:100"]"#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(import.policies[0].entries.len(), 1);
    assert!(import.policies[0].entries[0].prefix.is_none());
    assert_eq!(import.policies[0].entries[0].match_community.len(), 1);
}

#[test]
fn prefix_and_community_parses() {
    let toml = community_toml(
        r#"prefix = "10.0.0.0/8"
            action = "deny"
            match_community = ["RT:65001:100", "RO:65002:200"]"#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert!(import.policies[0].entries[0].prefix.is_some());
    assert_eq!(import.policies[0].entries[0].match_community.len(), 2);
}

#[test]
fn ge_without_prefix_rejected() {
    let toml = community_toml(
        r#"action = "deny"
ge = 16
match_community = ["RT:65001:100"]"#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn neither_prefix_nor_community_rejected() {
    let toml = community_toml(r#"action = "deny""#);
    assert!(parse(&toml).is_err());
}

#[test]
fn invalid_community_string_rejected() {
    let toml = community_toml(
        r#"action = "deny"
match_community = ["INVALID"]"#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn ipv4_community_parses() {
    let toml = community_toml(
        r#"action = "deny"
            match_community = ["RT:192.0.2.1:100"]"#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(import.policies[0].entries[0].match_community.len(), 1);
}

// --- AS_PATH regex config tests ---

#[test]
fn match_as_path_only_parses() {
    let toml = community_toml(
        r#"action = "permit"
            match_as_path = "^65100_""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(import.policies[0].entries.len(), 1);
    assert!(import.policies[0].entries[0].prefix.is_none());
    assert!(import.policies[0].entries[0].match_as_path.is_some());
}

#[test]
fn match_as_path_with_prefix_parses() {
    let toml = community_toml(
        r#"action = "deny"
            prefix = "10.0.0.0/8"
            match_as_path = "_65200_""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert!(import.policies[0].entries[0].prefix.is_some());
    assert!(import.policies[0].entries[0].match_as_path.is_some());
}

#[test]
fn match_as_path_invalid_regex_rejected() {
    let toml = community_toml(
        r#"action = "deny"
            match_as_path = "[invalid""#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn neither_prefix_nor_community_nor_aspath_rejected() {
    let toml = community_toml(r#"action = "deny""#);
    assert!(parse(&toml).is_err());
}

#[test]
fn set_route_communities_use_rfc_admin_specific_encodings_for_add_and_remove() {
    // Red proof: routing numeric AS4 or dotted-IPv4 administrators through the
    // old type-0x00-only TOML builders makes the exact byte matrix fail (or
    // rejects the AS4 values); dropping original spelling makes the IPv4 rows
    // become type 0x02, and wiring only add or remove breaks the parity assert.
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = [
                "RT:65001:100", "RO:65001:200",
                "RT:100000:100", "RO:100000:200",
                "RT:192.0.2.1:100", "RO:192.0.2.1:200",
                "RT:65535:70000"
            ]
            set_community_remove = [
                "RT:65001:100", "RO:65001:200",
                "RT:100000:100", "RO:100000:200",
                "RT:192.0.2.1:100", "RO:192.0.2.1:200",
                "RT:65535:70000"
            ]"#,
    );
    let cfg = parse(&toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let statement = &import.expect("import chain configured").policies[0].entries[0];
    let expected = vec![
        0x0002_FDE9_0000_0064,
        0x0003_FDE9_0000_00C8,
        0x0202_0001_86A0_0064,
        0x0203_0001_86A0_00C8,
        0x0102_C000_0201_0064,
        0x0103_C000_0201_00C8,
        0x0002_FFFF_0001_1170,
    ];
    let added: Vec<u64> = statement
        .modifications
        .extended_communities_add
        .iter()
        .map(|community| community.as_u64())
        .collect();
    let removed: Vec<u64> = statement
        .modifications
        .extended_communities_remove
        .iter()
        .map(|community| community.as_u64())
        .collect();
    assert_eq!(added, expected);
    assert_eq!(removed, expected);
}

#[test]
fn set_route_community_rejects_as4_local_that_exceeds_u16() {
    // Red proof: deleting `parse_community_match`'s AS4 local-width check
    // routes the invalid value to the shared encoder, changing this exact
    // parser diagnostic and failing the equality assertion below.
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = ["RT:100000:70000"]"#,
    );
    let ConfigError::InvalidPolicyEntry { reason } = parse(&toml).unwrap_err() else {
        panic!("expected invalid policy entry")
    };
    assert_eq!(
        reason,
        "invalid local admin 70000: exceeds 65535 for 4-octet ASN 100000"
    );
}

#[test]
fn set_route_community_rejects_ipv4_local_that_exceeds_u16() {
    // Red proof: deleting `parse_community_match`'s dotted-IPv4 local-width
    // check routes the invalid value to the shared encoder and changes this
    // exact parser diagnostic; treating the spelling as an ASN also changes
    // the administrator kind.
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_remove = ["RO:192.0.2.1:70000"]"#,
    );
    let ConfigError::InvalidPolicyEntry { reason } = parse(&toml).unwrap_err() else {
        panic!("expected invalid policy entry")
    };
    assert_eq!(
        reason,
        "invalid local admin 70000: exceeds 65535 for IPv4 global administrator 192.0.2.1"
    );
}

#[test]
fn ov_well_known_ext_community_names_in_toml_policy() {
    // RFC 8097 origin-validation states ride the well-known-name path
    // in match and set positions.
    let toml = community_toml(
        r#"action = "permit"
            match_community = ["OV_INVALID"]
            set_community_add = ["OV_VALID"]
            set_community_remove = ["OV_NOT_FOUND"]"#,
    );
    let cfg = parse(&toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("import chain configured");
    let stmt = &chain.policies[0].entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::ExactExt(
            rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_INVALID.as_u64()
        )]
    );
    assert_eq!(
        stmt.modifications.extended_communities_add,
        vec![rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_VALID]
    );
    assert_eq!(
        stmt.modifications.extended_communities_remove,
        vec![rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_NOT_FOUND]
    );
}

#[test]
fn set_community_rt_2byte_asn_accepted() {
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = ["RT:65535:100"]"#,
    );
    assert!(parse(&toml).is_ok());
}

// -----------------------------------------------------------------------
// Named policies + policy chaining
// -----------------------------------------------------------------------

#[test]
fn empty_policy_definition_name_is_rejected() {
    // The empty name is the inline-policy sentinel in the explain
    // surface; a quoted-empty definition key must not collide with it.
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.""]
default_action = "deny"
[[policy.definitions."".statements]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidPolicyEntry { .. }),
        "{err:?}"
    );
}

#[test]
fn named_policy_parses() {
    let config = parse(&named_policy_toml()).unwrap();
    assert_eq!(config.policy.definitions.len(), 2);
    assert!(config.policy.definitions.contains_key("reject-bogons"));
    assert!(config.policy.definitions.contains_key("set-lp"));
}

#[test]
fn named_policy_default_deny() {
    let config = parse(&named_policy_toml()).unwrap();
    let def = &config.policy.definitions["reject-bogons"];
    assert_eq!(def.default_action, "deny");
    let policy = parse_named_policy(
        "reject-bogons",
        def,
        &config.policy.neighbor_sets,
        &config.peer_groups,
    )
    .unwrap();
    assert_eq!(policy.default_action, PolicyAction::Deny);
}

#[test]
fn empty_statements_deny_is_valid() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.deny-all]
default_action = "deny"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let def = &config.policy.definitions["deny-all"];
    let policy = parse_named_policy(
        "deny-all",
        def,
        &config.policy.neighbor_sets,
        &config.peer_groups,
    )
    .unwrap();
    assert_eq!(policy.entries.len(), 0);
    assert_eq!(policy.default_action, PolicyAction::Deny);
}

#[test]
fn undefined_policy_in_chain_is_error() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy]
import_chain = ["nonexistent"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[test]
fn global_import_chain_works() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.set-lp]
[[policy.definitions.set-lp.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 200

[policy]
import_chain = ["set-lp"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let chain = config.import_chain().unwrap().unwrap();
    assert_eq!(chain.policies.len(), 1);
    assert_eq!(chain.policies[0].entries.len(), 1);
}

#[test]
fn neighbor_import_chain_overrides_global() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.global-pol]
[[policy.definitions.global-pol.statements]]
action = "deny"
prefix = "10.0.0.0/8"

[policy.definitions.peer-pol]
[[policy.definitions.peer-pol.statements]]
action = "permit"
prefix = "192.168.0.0/16"
set_local_pref = 300

[policy]
import_chain = ["global-pol"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
import_policy_chain = ["peer-pol"]
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let (_, _, import, _) = &peers[1]; // skip the first neighbor from valid_toml
    let chain = import.as_ref().unwrap();
    // Peer chain should have peer-pol, not global-pol
    assert_eq!(
        chain.policies[0].entries[0].modifications.set_local_pref,
        Some(300)
    );
}

#[test]
fn inline_and_chain_mutually_exclusive() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.some-pol]
[[policy.definitions.some-pol.statements]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
import_policy_chain = ["some-pol"]

[[neighbors.import_policy]]
action = "deny"
prefix = "192.168.0.0/16"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(err.to_string().contains("mutually exclusive"));
}

#[test]
fn inline_policy_still_works() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003

[[neighbors.import_policy]]
action = "deny"
prefix = "192.168.0.0/16"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let (_, _, import, _) = &peers[1];
    let chain = import.as_ref().unwrap();
    assert_eq!(chain.policies.len(), 1);
    assert_eq!(chain.policies[0].entries[0].action, PolicyAction::Deny);
}

#[test]
fn no_policy_falls_back_to_global_chain() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.global-pol]
[[policy.definitions.global-pol.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 150

[policy]
import_chain = ["global-pol"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    // Second neighbor (first is from valid_toml) has no per-peer policy
    let (_, _, import, _) = &peers[1];
    let chain = import.as_ref().unwrap();
    assert_eq!(
        chain.policies[0].entries[0].modifications.set_local_pref,
        Some(150)
    );
}

#[test]
fn neighbor_set_and_route_shape_policy_fields_parse() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.rs-clients]
hold_time = 90

[policy.neighbor_sets.ixp]
addresses = ["10.0.0.3"]
remote_asns = [65003]
peer_groups = ["rs-clients"]

[policy.definitions.prefer-external]
[[policy.definitions.prefer-external.statements]]
action = "permit"
match_neighbor_set = "ixp"
match_route_type = "external"
match_next_hop = "10.0.0.3"
match_local_pref_ge = 200
match_med_le = 50
set_local_pref = 250

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rs-clients"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let def = &config.policy.definitions["prefer-external"];
    let policy = parse_named_policy(
        "prefer-external",
        def,
        &config.policy.neighbor_sets,
        &config.peer_groups,
    )
    .unwrap();
    let statement = &policy.entries[0];
    assert!(statement.match_neighbor_set.is_some());
    assert_eq!(statement.match_route_type, Some(RouteType::External));
    assert_eq!(statement.match_next_hop, Some("10.0.0.3".parse().unwrap()));
    assert_eq!(statement.match_local_pref_ge, Some(200));
    assert_eq!(statement.match_med_le, Some(50));
    assert_eq!(statement.modifications.set_local_pref, Some(250));
}

#[test]
fn match_next_hop_invalid_rejected() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.bad]
[[policy.definitions.bad.statements]]
action = "permit"
match_next_hop = "not-an-ip"
set_local_pref = 200

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
        GLOBAL_HEADER = valid_toml()
    );

    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    assert!(err.to_string().contains("invalid match_next_hop"));
}
