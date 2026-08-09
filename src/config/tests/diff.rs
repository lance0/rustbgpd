use super::*;

#[test]
fn diff_neighbors_detects_added() {
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let new = vec![
        test_neighbor("10.0.0.1", 65001),
        test_neighbor("10.0.0.2", 65002),
    ];
    let diff = super::diff_neighbors(&old, &new);
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].address, "10.0.0.2");
}

#[test]
fn diff_neighbors_detects_removed() {
    let old = vec![
        test_neighbor("10.0.0.1", 65001),
        test_neighbor("10.0.0.2", 65002),
    ];
    let new = vec![test_neighbor("10.0.0.1", 65001)];
    let diff = super::diff_neighbors(&old, &new);
    assert!(diff.added.is_empty());
    assert!(diff.changed.is_empty());
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(
        diff.removed[0],
        PeerKey::new("10.0.0.2".parse::<IpAddr>().unwrap(), None)
    );
}

#[test]
fn diff_neighbors_detects_changed() {
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let new = vec![test_neighbor("10.0.0.1", 65099)];
    let diff = super::diff_neighbors(&old, &new);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);
    assert_eq!(diff.changed[0].remote_asn, 65099);
}

#[test]
fn diff_neighbors_no_changes() {
    let peers = vec![
        test_neighbor("10.0.0.1", 65001),
        test_neighbor("10.0.0.2", 65002),
    ];
    let diff = super::diff_neighbors(&peers, &peers);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
}

#[test]
fn load_canonicalizes_static_neighbor_address_spelling() {
    // Uppercase, zero-expanded, and fully-expanded spellings all load as
    // the one canonical form, so raw-string address comparisons against
    // `IpAddr::to_string()` cannot silently miss.
    for spelling in [
        "2001:db8::1",
        "2001:DB8::1",
        "2001:db8:0:0:0:0:0:1",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
    ] {
        let config = loaded_config_with_neighbor_address(spelling);
        assert_eq!(
            config.neighbors[0].address, "2001:db8::1",
            "spelling {spelling} must canonicalize"
        );
    }
}

#[test]
fn reload_with_respelled_ipv6_neighbor_diffs_empty() {
    // A representation-only respelling of the same IPv6 address is the
    // same peer: reload must plan no session teardown (no removed+added
    // pair) and no change.
    let old = loaded_config_with_neighbor_address("2001:db8::1");
    for respelled in [
        "2001:DB8::1",
        "2001:db8:0:0:0:0:0:1",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
    ] {
        let new = loaded_config_with_neighbor_address(respelled);
        let diff = super::diff_neighbors(&old.neighbors, &new.neighbors);
        assert!(
            diff.removed.is_empty(),
            "{respelled}: respelling must not plan a session teardown: {:?}",
            diff.removed
        );
        assert!(
            diff.added.is_empty(),
            "{respelled}: respelling must not plan a session add: {:?}",
            diff.added
        );
        assert!(
            diff.changed.is_empty(),
            "{respelled}: respelling is not a neighbor change"
        );
    }
}

#[test]
fn genuine_ipv6_address_change_still_diffs_removed_and_added() {
    // Canonicalization must not mask a real address change.
    let old = loaded_config_with_neighbor_address("2001:db8::1");
    let new = loaded_config_with_neighbor_address("2001:db8::2");
    let diff = super::diff_neighbors(&old.neighbors, &new.neighbors);
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(
        diff.removed[0],
        PeerKey::new("2001:db8::1".parse::<IpAddr>().unwrap(), None)
    );
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].address, "2001:db8::2");
    assert!(diff.changed.is_empty());
}

#[test]
fn ipv4_neighbor_address_load_is_identity() {
    // `IpAddr` round-trip is the identity for a valid dotted quad; pin it.
    let config = loaded_config_with_neighbor_address("192.0.2.1");
    assert_eq!(config.neighbors[0].address, "192.0.2.1");
}

#[test]
fn diff_neighbors_ignores_tcp_ao_only_changes_because_reload_pins_them() {
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let mut new_neighbor = test_neighbor("10.0.0.1", 65001);
    new_neighbor.tcp_ao = Some(
        TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: true,
            deprecated: false,
        }
        .into(),
    );

    let diff = super::diff_neighbors(&old, &[new_neighbor]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
}

#[test]
fn diff_neighbors_detects_prefix_orf_receive_only_change() {
    // ORF is negotiated in OPEN like add_path / families / role, so it is live
    // config (effective on the next session via the ReconcilePeers delete/re-add
    // path), NOT a startup-pinned resource like tcp_ao / bfd. A bare
    // prefix_orf_receive toggle must therefore surface as a changed neighbor,
    // not a silent no-op (the inverse of the tcp_ao case above).
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let mut new_neighbor = test_neighbor("10.0.0.1", 65001);
    new_neighbor.prefix_orf_receive = Some(true);

    let diff = super::diff_neighbors(&old, &[new_neighbor]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);

    let changes = super::describe_neighbor_changes(&old[0], &diff.changed[0]);
    assert!(
        changes
            .iter()
            .any(|c| c.render().contains("prefix_orf_receive")),
        "describe_neighbor_changes must name prefix_orf_receive, got {changes:?}"
    );
}

#[test]
fn diff_neighbors_detects_disable_ipv4_unicast_only_change() {
    // disable_ipv4_unicast is an OPEN-time property like prefix_orf_receive:
    // live config, effective on the next session via ReconcilePeers. A bare
    // toggle must surface as a changed neighbor, not a silent no-op.
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let mut new_neighbor = test_neighbor("10.0.0.1", 65001);
    new_neighbor.disable_ipv4_unicast = Some(true);

    let diff = super::diff_neighbors(&old, &[new_neighbor]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);

    let changes = super::describe_neighbor_changes(&old[0], &diff.changed[0]);
    assert!(
        changes
            .iter()
            .any(|c| c.render().contains("disable_ipv4_unicast")),
        "describe_neighbor_changes must name disable_ipv4_unicast, got {changes:?}"
    );
}

#[test]
fn diff_config_flags_tcp_ao_changes_as_restart_required() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "old-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );
    let mut new = old.clone();
    new.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "new-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

    let diff = super::diff_config(&old, &new);
    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.has_restart_required_changes());
    assert!(!diff.has_reload_applied_changes());

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["neighbor_tcp_ao_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[[neighbors]].tcp_ao changed"));
    assert!(!text.contains("old-secret"));
    assert!(!text.contains("new-secret"));
}

/// ADR-0073 reversal: import explainability is opt-in. A config that
/// never mentions `[policy.explain]` must resolve to a disabled cache,
/// and an explicit `enabled = true` must behave exactly as before.
///
/// Pinned on the schema/serde default specifically — this is the path a
/// config file takes, and it is distinct from `TransportConfig::new`
/// (pinned in `crates/transport/src/config.rs`), which embedders reach
/// without ever loading a config file. Either default flipping back on
/// its own leaves the other construction path uncovered, so each gets
/// its own test.
#[test]
fn omitted_policy_explain_block_resolves_to_disabled() {
    let config = parse(valid_toml()).unwrap();
    assert!(
        !config.policy.explain.enabled,
        "an omitted [policy.explain] block must leave import explain off"
    );
    assert!(
        !config
            .resolve_neighbor(&config.neighbors[0])
            .unwrap()
            .transport_config
            .explain_enabled,
        "the disabled schema default must reach the per-session transport config"
    );

    // Opting in explicitly is unchanged: the cache is populated and
    // `cache_size` still defaults to the same 4096 entries per session.
    let opted_in = parse(&format!(
        "{}\n[policy.explain]\nenabled = true\n",
        valid_toml()
    ))
    .unwrap();
    assert!(opted_in.policy.explain.enabled);
    assert_eq!(opted_in.policy.explain.cache_size, 4096);
    let resolved = opted_in
        .resolve_neighbor(&opted_in.neighbors[0])
        .unwrap()
        .transport_config;
    assert!(
        resolved.explain_enabled,
        "explicit enabled = true must still enable the cache"
    );
    assert_eq!(resolved.explain_cache_size, 4096);
}

#[test]
fn resolve_neighbor_threads_policy_explain_settings() {
    // ADR-0073: the resolved-neighbor transport path (used by
    // snapshot-sync gRPC peer adds via PeerManager) must thread the
    // [policy.explain] knobs, not leave them at TransportConfig::new
    // defaults.
    let mut config = parse(valid_toml()).unwrap();
    config.policy.explain.enabled = false;
    config.policy.explain.cache_size = 256;
    let resolved = config.resolve_neighbor(&config.neighbors[0]).unwrap();
    assert!(
        !resolved.transport_config.explain_enabled,
        "enabled must propagate through resolve_neighbor"
    );
    assert_eq!(resolved.transport_config.explain_cache_size, 256);
}

#[test]
fn resolve_neighbor_threads_reject_retention_settings() {
    // LAN-472: the resolved-neighbor transport path must thread the
    // [policy.reject_retention] knobs, mirroring the [policy.explain]
    // threading above.
    let mut config = parse(valid_toml()).unwrap();
    config.policy.reject_retention.enabled = false;
    config.policy.reject_retention.capacity = 64;
    let resolved = config.resolve_neighbor(&config.neighbors[0]).unwrap();
    assert!(
        !resolved.transport_config.reject_retention_enabled,
        "enabled must propagate through resolve_neighbor"
    );
    assert_eq!(resolved.transport_config.reject_retention_capacity, 64);
}

#[test]
fn diff_config_flags_reject_retention_as_restart_required() {
    // LAN-472: a [policy.reject_retention] edit is restart-required-per-
    // peer and must be visible in `--diff` (JSON + text), matching the
    // [policy.explain] contract.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.policy.reject_retention.enabled = false;
    new.policy.reject_retention.capacity = 128;

    let diff = super::diff_config(&old, &new);
    assert!(diff.policy_reject_retention_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "a reject-retention-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["restart_required"]["policy_reject_retention_changed"],
        true
    );

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[policy.reject_retention]"), "{text}");
}

#[test]
fn diff_config_flags_policy_explain_as_restart_required() {
    // ADR-0073: a [policy.explain] edit is restart-required-per-peer and
    // must be visible in `--diff` (JSON + text), not silently dropped.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.policy.explain.enabled = false;
    new.policy.explain.cache_size = 512;

    let diff = super::diff_config(&old, &new);
    assert!(diff.policy_explain_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "an explain-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["policy_explain_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[policy.explain]"), "{text}");
}

#[test]
fn diff_config_no_policy_explain_change_is_clean() {
    let old = parse(valid_toml()).unwrap();
    let new = old.clone();
    let diff = super::diff_config(&old, &new);
    assert!(!diff.policy_explain_changed);
    assert!(!diff.has_actionable_changes());
}

#[test]
fn diff_config_flags_security_grpc_as_restart_required() {
    // LAN-286: `[security.grpc]` is resolved once at startup when the
    // gRPC listeners are built — an edit must classify as
    // restart-required, not vanish from the diff.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.security
        .grpc
        .roles
        .insert("observer-readonly".to_string(), GrpcRoleConfig::Observer);

    let diff = super::diff_config(&old, &new);
    assert!(diff.security_grpc_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "a security-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["security_grpc_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[security.grpc]"), "{text}");

    let sections = super::classify_config_transaction_v1(&diff);
    assert!(
        sections
            .restart_required_sections
            .contains(&"[security.grpc]".to_string()),
        "{sections:?}"
    );
}

#[test]
fn diff_config_flags_event_history_as_restart_required() {
    // LAN-286: every `[event_history]` field is restart-required (the
    // ADR-0072 outbox is configured once at startup) — an edit must
    // classify as restart-required, not vanish from the diff.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.event_history.enabled = !new.event_history.enabled;

    let diff = super::diff_config(&old, &new);
    assert!(diff.event_history_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "an event-history-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["event_history_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[event_history]"), "{text}");

    let sections = super::classify_config_transaction_v1(&diff);
    assert!(
        sections
            .restart_required_sections
            .contains(&"[event_history]".to_string()),
        "{sections:?}"
    );
}

#[test]
fn diff_config_flags_inbound_admission_as_restart_required() {
    // ADR-0120: every `[inbound_admission]` field is restart-required
    // (the accept-path limiter is built once at startup) — an edit must
    // classify as restart-required, not vanish from the diff.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.inbound_admission.enabled = !new.inbound_admission.enabled;

    let diff = super::diff_config(&old, &new);
    assert!(diff.inbound_admission_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "an inbound-admission-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["inbound_admission_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[inbound_admission]"), "{text}");

    let sections = super::classify_config_transaction_v1(&diff);
    assert!(
        sections
            .restart_required_sections
            .contains(&"[inbound_admission]".to_string()),
        "{sections:?}"
    );
}

#[test]
fn diff_config_pins_entire_neighbor_when_tcp_ao_changes() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].hold_time = Some(90);
    old.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "old-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );
    let mut new = old.clone();
    new.neighbors[0].hold_time = Some(120);
    new.neighbors[0].tcp_ao = Some(
        TcpAoConfig {
            key: "new-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.neighbors.changed.is_empty());
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
fn diff_config_pins_tcp_ao_neighbor_dependencies() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
import_policy_chain = ["keep"]

[peer_groups.rs-clients]
hold_time = 60

[policy.neighbor_sets.ixp]
peer_groups = ["rs-clients"]

[[policy.definitions.keep.statements]]
action = "permit"
match_neighbor_set = "ixp"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
md5_password = "md5-secret"
import_policy_chain = ["keep"]

[policy.definitions.keep]
default_action = "deny"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
"#;
    let old = parse(old_toml).unwrap();
    let new = parse(new_toml).unwrap();

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.peer_groups.changed.is_empty());
    assert!(diff.policy.definitions_changed.is_empty());
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
fn diff_config_pins_removed_tcp_ao_neighbor_dependencies() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
import_policy_chain = ["keep"]

[peer_groups.rs-clients]
hold_time = 60

[policy.neighbor_sets.ixp]
peer_groups = ["rs-clients"]

[[policy.definitions.keep.statements]]
action = "permit"
match_neighbor_set = "ixp"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert!(runtime.validate().is_ok());
    assert!(
        runtime
            .neighbors
            .iter()
            .any(|neighbor| neighbor.address == "10.0.0.2"
                && neighbor.peer_group.as_deref() == Some("secure")
                && neighbor.tcp_ao.is_some())
    );
    assert!(runtime.peer_groups.contains_key("secure"));
    assert!(runtime.peer_groups.contains_key("rs-clients"));
    assert!(runtime.policy.definitions.contains_key("keep"));
    assert!(runtime.policy.neighbor_sets.contains_key("ixp"));

    let diff = super::diff_config(&old, &runtime);
    assert!(diff.neighbors.removed.is_empty());
    assert!(diff.peer_groups.removed.is_empty());
    assert!(diff.policy.definitions_removed.is_empty());
    assert!(diff.policy.neighbor_sets_removed.is_empty());
}

#[test]
fn tcp_ao_pinning_preserves_inherited_global_policy_chains() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
import_chain = ["import-keep"]
export_chain = ["export-keep"]

[policy.definitions.import-keep]
default_action = "permit"

[policy.definitions.export-keep]
default_action = "permit"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert_eq!(runtime.policy.import_chain, vec!["import-keep"]);
    assert_eq!(runtime.policy.export_chain, vec!["export-keep"]);
    assert!(runtime.policy.definitions.contains_key("import-keep"));
    assert!(runtime.policy.definitions.contains_key("export-keep"));
    assert!(runtime.validate().is_ok());

    let diff = super::diff_config(&old, &runtime);
    assert!(!diff.policy.import_chain_changed);
    assert!(!diff.policy.export_chain_changed);
    assert!(diff.policy.definitions_removed.is_empty());
}

#[test]
fn tcp_ao_pinning_keeps_global_asn_with_removed_rr_neighbor() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65002
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert_eq!(runtime.global.asn, 65001);
    assert!(runtime.validate().is_ok());
    assert!(runtime.neighbors.iter().any(|neighbor| {
        neighbor.address == "10.0.0.2"
            && neighbor.remote_asn == 65001
            && neighbor.route_reflector_client == Some(true)
            && neighbor.tcp_ao.is_some()
    }));
}

#[test]
fn tcp_ao_pinning_keeps_global_asn_with_rotated_rr_neighbor() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65002
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
route_reflector_client = true
tcp_ao = { key = "new-secret", send_id = 2, recv_id = 2, algorithm = "hmac(sha256)" }
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert_eq!(runtime.global.asn, 65001);
    assert!(runtime.validate().is_ok());
    let neighbor = runtime
        .neighbors
        .iter()
        .find(|neighbor| neighbor.address == "10.0.0.2")
        .expect("pinned neighbor restored");
    assert_eq!(neighbor.remote_asn, 65001);
    assert_eq!(
        neighbor
            .tcp_ao
            .as_ref()
            .map(|tcp_ao| tcp_ao.0[0].key.as_str()),
        Some("old-secret")
    );
}

#[test]
fn diff_config_preserves_unrelated_policy_diff_when_tcp_ao_neighbor_is_pinned() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy.definitions.unrelated]
default_action = "permit"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
    let old = parse(old_toml).unwrap();
    let new = parse(new_toml).unwrap();

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert_eq!(diff.policy.definitions_added, vec!["unrelated"]);
    assert!(diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "fixture-heavy TCP-AO pinning regression"
)]
fn tcp_ao_pinning_keeps_new_unprotected_neighbor_peer_group_valid() {
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.peer_groups.insert(
        "new-group".to_string(),
        PeerGroupConfig {
            min_hold_time: None,
            hold_time: Some(60),
            send_hold_time: None,
            slow_peer_threshold_pct: None,
            slow_peer_duration: None,
            slow_peer_isolation: None,
            max_prefixes: None,
            max_prefixes_ipv4: None,
            max_prefixes_ipv6: None,
            max_prefixes_out_ipv4: None,
            max_prefixes_out_ipv6: None,
            max_prefix_restart_seconds: None,
            md5_password: None,
            ttl_security: None,
            bfd: None,
            families: Vec::new(),
            required_families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_peer_restart_time_max: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            orr_vantage: None,
            route_server_client: None,
            per_client_best: None,
            next_hop_ownership: None,
            interpret_rfc1997: None,
            rs_control_communities: None,
            role: None,
            strict_role: None,
            prefix_orf_receive: None,
            disable_ipv4_unicast: None,
            remove_private_as: None,
            add_path: None,
            log_level: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            import_policy_chain: Vec::new(),
            export_policy_chain: Vec::new(),
        },
    );
    new.neighbors.push(Neighbor {
        min_hold_time: None,
        address: "10.0.0.3".into(),
        interface: None,
        remote_asn: 65003,
        description: None,
        peer_group: Some("new-group".into()),
        hold_time: None,
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefixes_out_ipv4: None,
        max_prefixes_out_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        bfd: None,
        tcp_ao: Some(
            TcpAoConfig {
                key: "secret".into(),
                send_id: 1,
                recv_id: 1,
                algorithm: "hmac(sha256)".into(),
                preferred: false,
                deprecated: false,
            }
            .into(),
        ),
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
        per_client_best: None,
        next_hop_ownership: None,
        interpret_rfc1997: None,
        rs_control_communities: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
        log_level: None,
    });
    new.neighbors.push(Neighbor {
        min_hold_time: None,
        address: "10.0.0.4".into(),
        interface: None,
        remote_asn: 65004,
        description: None,
        peer_group: Some("new-group".into()),
        hold_time: None,
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefixes_out_ipv4: None,
        max_prefixes_out_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
        per_client_best: None,
        next_hop_ownership: None,
        interpret_rfc1997: None,
        rs_control_communities: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
        log_level: None,
    });

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut new, &old);

    assert_eq!(pinned, 1);
    assert!(new.validate().is_ok());
    assert!(new.neighbors.iter().any(|neighbor| {
        neighbor.address == "10.0.0.4" && neighbor.peer_group.as_deref() == Some("new-group")
    }));
    assert!(
        new.neighbors
            .iter()
            .all(|neighbor| neighbor.address != "10.0.0.3")
    );
}

#[test]
fn diff_config_does_not_mark_tcp_ao_neighbor_add_as_reload_applied() {
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.neighbors.push(Neighbor {
        min_hold_time: None,
        address: "10.0.0.3".into(),
        interface: None,
        remote_asn: 65003,
        description: None,
        peer_group: None,
        hold_time: None,
        send_hold_time: None,
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefixes_out_ipv4: None,
        max_prefixes_out_ipv6: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        bfd: None,
        tcp_ao: Some(
            TcpAoConfig {
                key: "secret".into(),
                send_id: 1,
                recv_id: 1,
                algorithm: "hmac(sha256)".into(),
                preferred: false,
                deprecated: false,
            }
            .into(),
        ),
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
        per_client_best: None,
        next_hop_ownership: None,
        interpret_rfc1997: None,
        rs_control_communities: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
        log_level: None,
    });

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.neighbors.added.is_empty());
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
fn describe_neighbor_changes_detects_field_diffs() {
    let old = test_neighbor("10.0.0.1", 65001);
    let mut new = old.clone();
    new.remote_asn = 65099;
    new.hold_time = Some(45);
    new.families = vec!["ipv4_unicast".into(), "ipv6_unicast".into()];

    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(changes.len(), 3);
    assert!(changes[0].render().contains("remote_asn"));
    assert!(changes[1].render().contains("hold_time"));
    assert!(changes[2].render().contains("families"));
}

#[test]
fn describe_neighbor_changes_empty_when_equal() {
    let n = test_neighbor("10.0.0.1", 65001);
    let changes = super::describe_neighbor_changes(&n, &n);
    assert!(changes.is_empty());
}

#[test]
fn describe_neighbor_changes_hides_md5_value() {
    let old = test_neighbor("10.0.0.1", 65001);
    let mut new = old.clone();
    new.md5_password = Some("secret".into());

    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert!(changes[0].render().contains("<changed>"));
    assert!(!changes[0].render().contains("secret"));
}

#[test]
fn describe_neighbor_changes_hides_tcp_ao_key() {
    let old = test_neighbor("10.0.0.1", 65001);
    let mut new = old.clone();
    new.tcp_ao = Some(
        TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: true,
            deprecated: false,
        }
        .into(),
    );

    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].render(), "tcp_ao: <changed>  [restart required]");
    assert!(!changes[0].render().contains("secret"));
    assert_eq!(changes[0].old, serde_json::Value::Null);
    assert_eq!(changes[0].new, serde_json::Value::Null);
}

// ── LAN-321: operator-grade diff rendering + impact classification ───

#[test]
fn config_field_impact_surfaces_reload_matrix_classes() {
    // Mutation-red for min_hold_time: removing its impact-map or either
    // neighbor/group diff row breaks the exact assertions below.
    use super::ConfigFieldImpact::{HotApplied, RestartRequired, SessionReset};
    let class = |field: &str| super::config_field_impact(field).map(|(class, _)| class);

    // Session-affecting: a hold_time edit classifies as session reset.
    assert_eq!(class("hold_time"), Some(SessionReset));
    assert_eq!(class("min_hold_time"), Some(SessionReset));
    assert_eq!(class("families"), Some(SessionReset));
    assert_eq!(class("md5_password"), Some(SessionReset));
    // Hot-applied: a description edit never touches the session.
    assert_eq!(class("description"), Some(HotApplied));
    assert_eq!(class("gr_peer_restart_time_max"), Some(HotApplied));
    assert_eq!(class("log_level"), Some(HotApplied));
    assert_eq!(class("max_prefixes"), Some(HotApplied));
    // Restart-required, matching the reload matrix pins.
    assert_eq!(class("tcp_ao"), Some(RestartRequired));
    assert_eq!(class("bfd"), Some(RestartRequired));
    // LAN-341 adjudication: both flow through the reconcile rebuild path
    // (remote_asn is not part of the diff key; a peer_group reassignment
    // changes the peer's effective inherited config), so both are honest
    // session resets in the diff annotations.
    assert_eq!(class("remote_asn"), Some(SessionReset));
    assert_eq!(class("peer_group"), Some(SessionReset));

    let old = test_neighbor("10.0.0.2", 65002);
    let mut new = old.clone();
    new.min_hold_time = Some(30);
    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].field, "min_hold_time");
    assert_eq!(changes[0].impact, Some(SessionReset));

    let old_group = PeerGroupConfig::default();
    let mut new_group = old_group.clone();
    new_group.min_hold_time = Some(30);
    let group_changes = super::describe_peer_group_changes(&old_group, &new_group);
    assert_eq!(group_changes.len(), 1);
    assert_eq!(group_changes[0].field, "min_hold_time");
    assert_eq!(group_changes[0].impact, Some(SessionReset));
}

// ── LAN-341: hot-applicable partition predicate ───────────────────────

#[test]
fn neighbor_change_hot_applicable_partitions_by_impact_class() {
    let old = test_neighbor("10.0.0.2", 65002);

    // Hot-applied-only edit → in-place apply.
    let mut hot = old.clone();
    hot.description = Some("edge".to_string());
    hot.gr_peer_restart_time_max = Some(300);
    hot.max_prefixes = Some(500);
    hot.import_policy_chain = vec!["allow-all".to_string()];
    assert!(super::neighbor_change_hot_applicable(&old, &hot));

    // No change at all → not hot-applicable (nothing to apply; the
    // caller's diff should not have flagged it).
    assert!(!super::neighbor_change_hot_applicable(&old, &old));

    // A session-reset field alone → rebuild.
    let mut reset = old.clone();
    reset.hold_time = Some(30);
    assert!(!super::neighbor_change_hot_applicable(&old, &reset));

    let mut minimum = old.clone();
    minimum.min_hold_time = Some(30);
    assert!(!super::neighbor_change_hot_applicable(&old, &minimum));

    // Mixed hot + session-reset → rebuild (one bounce applies both).
    let mut mixed = hot.clone();
    mixed.hold_time = Some(30);
    assert!(!super::neighbor_change_hot_applicable(&old, &mixed));

    // remote_asn and peer_group edits are session resets, never hot.
    let mut asn = old.clone();
    asn.remote_asn = 65003;
    assert!(!super::neighbor_change_hot_applicable(&old, &asn));
    let mut group = old.clone();
    group.peer_group = Some("ix".to_string());
    assert!(!super::neighbor_change_hot_applicable(&old, &group));
}

#[test]
fn slow_peer_edit_on_static_neighbor_takes_session_rebuild_path() {
    let old = test_neighbor("10.0.0.2", 65002);
    let mut new = old.clone();
    new.slow_peer_threshold_pct = Some(25);
    new.slow_peer_duration = Some(10);
    new.slow_peer_isolation = Some(true);

    // Detected: a slow_peer-only edit must be visible to the reconciler
    // at all — it was silently invisible to `diff_neighbors` before.
    let diff = super::diff_neighbors(std::slice::from_ref(&old), std::slice::from_ref(&new));
    assert_eq!(
        diff.changed.len(),
        1,
        "a slow_peer-only edit must be reported by diff_neighbors"
    );

    // Reported: `--diff` / reload logging must name all three fields,
    // classed session-reset (captured into the session transport config).
    let changes = super::describe_neighbor_changes(&old, &new);
    let fields: Vec<&str> = changes.iter().map(|change| change.field).collect();
    for field in [
        "slow_peer_threshold_pct",
        "slow_peer_duration",
        "slow_peer_isolation",
    ] {
        assert!(
            fields.contains(&field),
            "describe_neighbor_changes must name {field}, got {fields:?}"
        );
    }
    assert!(
        changes
            .iter()
            .all(|change| change.impact == Some(super::ConfigFieldImpact::SessionReset)),
        "slow_peer fields must classify as session reset: {changes:?}"
    );

    // Applied: the reload partition must take the session-rebuild path,
    // never hot-apply in place.
    assert!(
        !super::neighbor_change_hot_applicable(&old, &new),
        "a slow_peer edit must rebuild the session, not hot-apply"
    );
}

#[test]
fn slow_peer_edit_on_peer_group_keeps_conservative_reshape() {
    let old_group = PeerGroupConfig::default();
    let mut new_group = old_group.clone();
    new_group.slow_peer_threshold_pct = Some(25);
    new_group.slow_peer_duration = Some(10);
    new_group.slow_peer_isolation = Some(true);

    // Detected: diff_peer_groups compares whole structs, so the group
    // edit is visible.
    let old_map = std::collections::HashMap::from([("ixp".to_string(), old_group.clone())]);
    let new_map = std::collections::HashMap::from([("ixp".to_string(), new_group.clone())]);
    let diff = super::diff_peer_groups(&old_map, &new_map);
    assert_eq!(
        diff.changed,
        vec!["ixp".to_string()],
        "a group slow_peer edit must be reported as changed"
    );

    // Applied: the group path stays on the conservative reshape
    // (delete + re-add) fallback — never hot-applied to members in place.
    assert!(
        !super::peer_group_change_hot_applicable(&old_group, &new_group),
        "a group slow_peer edit must reshape members, not hot-apply"
    );
}

#[test]
fn config_diff_human_output_is_operator_grade() {
    // Mixed diff: one added, one changed (hot + session-reset fields),
    // one untouched neighbor.
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors = vec![
        test_neighbor("10.0.0.2", 65002),
        test_neighbor("10.0.0.9", 65009),
    ];
    old.neighbors[0].hold_time = Some(90);
    let mut new = old.clone();
    new.neighbors[0].hold_time = Some(30);
    new.neighbors[0].description = Some("edge".to_string());
    new.neighbors.push(test_neighbor("10.0.0.3", 65003));

    let diff = super::diff_config(&old, &new);
    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());

    // The 0.50.0 defect: Rust Debug formatting leaked into operator output.
    assert!(!text.contains("Some("), "{text}");
    assert!(!text.contains("None"), "{text}");

    assert!(text.contains("+ 10.0.0.3 (AS 65003)"), "{text}");
    assert!(
        text.contains("hold_time: 90 → 30  [session reset: OPEN renegotiation]"),
        "{text}"
    );
    assert!(
        text.contains("description: (unset) → edge  [hot-applied]"),
        "{text}"
    );
    assert!(
        !text.contains("10.0.0.9"),
        "unchanged neighbors must not appear: {text}"
    );
    assert!(
        text.ends_with("Plan: 1 to add, 1 to change · 1 session will reset\n"),
        "{text}"
    );
}

#[test]
fn config_diff_json_changes_have_stable_field_shape() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors = vec![test_neighbor("10.0.0.2", 65002)];
    old.neighbors[0].hold_time = Some(90);
    let mut new = old.clone();
    new.neighbors[0].hold_time = Some(30);
    new.neighbors[0].description = Some("edge".to_string());

    let diff = super::diff_config(&old, &new);
    let json = super::config_diff_json_value(&diff);

    let changes = &json["reload_applied"]["neighbors"]["changed"][0]["changes"];
    // describe order: description before hold_time.
    assert_eq!(changes[0]["field"], "description");
    assert_eq!(changes[0]["old"], serde_json::Value::Null);
    assert_eq!(changes[0]["new"], "edge");
    assert_eq!(changes[0]["impact"], "hot_applied");
    assert_eq!(changes[1]["field"], "hold_time");
    assert_eq!(changes[1]["old"], 90);
    assert_eq!(changes[1]["new"], 30);
    assert_eq!(changes[1]["impact"], "session_reset");

    assert_eq!(json["summary"]["neighbors_added"], 0);
    assert_eq!(json["summary"]["neighbors_changed"], 1);
    assert_eq!(json["summary"]["neighbors_removed"], 0);
    assert_eq!(json["summary"]["sessions_will_reset"], 1);
    assert_eq!(json["summary"]["restart_required"], false);
}

#[test]
fn config_diff_summary_line_covers_restart_and_no_reset_cases() {
    // Hot-applied-only change: no session resets expected.
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors = vec![test_neighbor("10.0.0.2", 65002)];
    let mut new = old.clone();
    new.neighbors[0].description = Some("edge".to_string());
    let diff = super::diff_config(&old, &new);
    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(
        text.ends_with("Plan: 1 to change · no session resets expected\n"),
        "{text}"
    );

    // Restart-required change ([policy.explain]): the summary names the
    // restart and makes no "no resets" claim.
    let mut new = old.clone();
    new.policy.explain.cache_size = 512;
    let diff = super::diff_config(&old, &new);
    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(
        text.ends_with("Plan: no neighbor changes · daemon restart required for some changes\n"),
        "{text}"
    );
    assert!(!text.contains("no session resets expected"), "{text}");
}

#[test]
fn tcp_ao_debug_redacts_key() {
    let tcp_ao = TcpAoConfig {
        key: "secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: false,
        deprecated: false,
    };

    let rendered = format!("{tcp_ao:?}");

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("secret"));
}

// ── Config diff tests ────────────────────────────────────────────────

#[test]
fn diff_config_identical_has_no_changes() {
    let config = parse(valid_toml()).unwrap();
    let diff = super::diff_config(&config, &config);
    assert!(!diff.has_any_changes());
}

#[test]
fn diff_config_neighbor_added() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
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
description = "peer-1"
hold_time = 90

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.neighbors.added.len(), 1);
    assert_eq!(diff.neighbors.added[0].address, "10.0.0.3");
    assert_eq!(diff.neighbors.added[0].remote_asn, 65003);
    assert!(diff.neighbors.removed.is_empty());
    assert!(diff.neighbors.changed.is_empty());
}

#[test]
fn diff_config_neighbor_removed() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.neighbors.removed.len(), 1);
    assert_eq!(diff.neighbors.removed[0], "10.0.0.2");
}

#[test]
fn diff_config_neighbor_changed() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
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
description = "peer-1"
hold_time = 45
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.neighbors.changed.len(), 1);
    assert_eq!(diff.neighbors.changed[0].address, "10.0.0.2");
    assert!(
        diff.neighbors.changed[0]
            .changes
            .iter()
            .any(|c| c.render().contains("hold_time"))
    );
}

#[test]
fn diff_config_global_change_flags_restart() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.99"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert!(diff.global_changed);
    assert!(!diff.rpki_changed);
}

#[test]
fn warm_cache_checkpoint_toggle_is_restart_required_and_defaults_off() {
    let old = parse(valid_toml()).unwrap();
    assert!(!old.global.warm_cache_checkpoint_on_shutdown);
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nwarm_cache_checkpoint_on_shutdown = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(new.global.warm_cache_checkpoint_on_shutdown);
    assert!(diff.global_changed);
    assert!(diff.has_restart_required_changes());
    assert!(!diff.has_reload_applied_changes());
}

#[test]
fn diff_config_honor_graceful_shutdown_only_is_reload_applied_not_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_graceful_shutdown = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(
        !diff.global_changed,
        "hot-applied honor_graceful_shutdown must not set the coarse restart bucket"
    );
    assert!(diff.honor_graceful_shutdown_changed);
    assert!(!diff.has_restart_required_changes());
    assert!(diff.has_reload_applied_changes());
}

#[test]
fn diff_config_honor_blackhole_only_is_reload_applied_not_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_blackhole = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(
        !diff.global_changed,
        "hot-applied honor_blackhole must not set the coarse restart bucket"
    );
    assert!(!diff.blackhole_fib_discard_changed);
    assert!(diff.honor_blackhole_changed);
    assert!(!diff.has_restart_required_changes());
    assert!(diff.has_reload_applied_changes());
}

#[test]
fn diff_config_role_change_is_reload_applied() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "hold_time = 90\n",
        "hold_time = 90\nrole = \"provider\"\nstrict_role = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(
        diff.has_reload_applied_changes(),
        "PeerManager applies Role capability changes by reconfiguring the peer session"
    );
    assert!(
        diff.neighbors
            .changed
            .iter()
            .any(|summary| summary.address == "10.0.0.2"
                && summary
                    .changes
                    .iter()
                    .any(|change| change.render().contains("role"))
                && summary
                    .changes
                    .iter()
                    .any(|change| change.render().contains("strict_role"))),
        "neighbor details must explain role/strict_role drift: {:?}",
        diff.neighbors.changed
    );
}

#[test]
fn diff_config_peer_group_added() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
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
description = "peer-1"
hold_time = 90

[peer_groups.upstream]
hold_time = 30
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.peer_groups.added, vec!["upstream"]);
}

#[test]
fn diff_config_policy_definition_added() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
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
description = "peer-1"
hold_time = 90

[policy.definitions.reject-bogons]
default_action = "permit"

[[policy.definitions.reject-bogons.statements]]
action = "deny"
prefix = "0.0.0.0/0"
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.policy.definitions_added, vec!["reject-bogons"]);
}

#[test]
fn diff_config_json_serializes() {
    let old = parse(valid_toml()).unwrap();
    let diff = super::diff_config(&old, &old);
    let json = serde_json::to_string(&diff).unwrap();
    assert!(json.contains("\"global_changed\":false"));
    // EVPN-instance drift must appear in the serialized diff so JSON
    // consumers (CI guards, dashboards) can act on it.
    assert!(
        json.contains("\"evpn_instances_changed\":false"),
        "expected evpn_instances_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"honor_graceful_shutdown_changed\":false"),
        "expected honor_graceful_shutdown_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"honor_blackhole_changed\":false"),
        "expected honor_blackhole_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"evpn_ip_vrfs_changed\":false"),
        "expected evpn_ip_vrfs_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"ethernet_segments_changed\":false"),
        "expected ethernet_segments_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"fib_tables_changed\":false"),
        "expected fib_tables_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"apply_bum_enforcement_changed\":false"),
        "expected apply_bum_enforcement_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"blackhole_fib_discard_changed\":false"),
        "expected blackhole_fib_discard_changed in serialized diff: {json}"
    );
}

#[test]
fn diff_peer_group_changes_detects_field_diffs() {
    let old = PeerGroupConfig {
        hold_time: Some(90),
        send_hold_time: None,
        ..Default::default()
    };
    let new = PeerGroupConfig {
        hold_time: Some(45),
        send_hold_time: None,
        ..Default::default()
    };
    let changes = super::describe_peer_group_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert!(changes[0].render().contains("hold_time"));
    assert!(changes[0].render().contains("90"));
    assert!(changes[0].render().contains("45"));
}

/// Policy-only edits are reload-applied (per-named definitions
/// flow through `apply_policy_change` on SIGHUP).
#[test]
fn diff_config_named_policy_only_is_reload_applied() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
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
description = "peer-1"
hold_time = 90

[policy.definitions.new-policy]
default_action = "deny"
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert!(
        diff.has_reload_applied_changes(),
        "named policy add must be reload-applied"
    );
    assert!(
        !diff.has_informational_changes(),
        "named policy edits no longer fall in the informational bucket"
    );
}

#[test]
fn reload_matrix_documents_every_neighbor_field() {
    let matrix = load_reload_matrix();
    let section = reload_matrix_section(&matrix, "## `[[neighbors]]`", "## `[peer_groups.<name>]`");
    for field in RELOAD_MATRIX_NEIGHBOR_FIELDS {
        let needle = format!("`{field}`");
        assert!(
            section.contains(&needle),
            "Neighbor field {needle} is in RELOAD_MATRIX_NEIGHBOR_FIELDS \
             (src/config/tests/mod.rs) but absent from docs/reload-matrix.md. \
             Either add a row for it in the [[neighbors]] section of the \
             matrix, or remove the entry from the list."
        );
    }
}

#[test]
fn reload_matrix_documents_every_peer_group_field() {
    let matrix = load_reload_matrix();
    let section = reload_matrix_section(
        &matrix,
        "## `[peer_groups.<name>]`",
        "## `[[dynamic_neighbors]]`",
    );
    for field in RELOAD_MATRIX_PEER_GROUP_FIELDS {
        let needle = format!("`{field}`");
        assert!(
            section.contains(&needle),
            "PeerGroupConfig field {needle} is in \
             RELOAD_MATRIX_PEER_GROUP_FIELDS (src/config/tests/mod.rs) but \
             absent from docs/reload-matrix.md. Either add a row for it \
             in the [[peer_groups]] section of the matrix, or remove the \
             entry from the list."
        );
    }
}

/// The name-coverage tests above only prove a field *appears* in the
/// matrix. This one pins the CLASS column (live vs restart-required) for
/// the knobs where the class is load-bearing — a docs-vs-reality drift on
/// these actively misleads an operator about whether a SIGHUP suffices.
///
/// `log_level` is now genuinely live (re-applied on SIGHUP via the
/// telemetry tracing reload handle), so the doc claim is finally true; if
/// someone regresses it back to inert and re-marks the row restart-required
/// (or vice versa) this fails. `tcp_ao` pins its deliberately narrow SIGHUP
/// exception: add-only install, observation-gated selection, and deletion of
/// deprecated unselected keys are live, while key edits and selected or
/// nondeprecated-key deletion remain restart-required. `bfd` pins the
/// unconditional restart-required side so a blanket "mark everything live"
/// edit also fails. `ebgp_requires_policy` pins the ADR-0112 RFC 8212
/// enforcement mode: re-marking it live would tell operators a SIGHUP can flip
/// import and export on every EBGP session, which the reload path refuses.
#[test]
fn reload_matrix_pins_load_bearing_field_classes() {
    let matrix = load_reload_matrix();
    for (field, class_cell) in [
        ("log_level", "| live |"),
        (
            "tcp_ao",
            "| live (ordered rotation generations) / otherwise restart-required |",
        ),
        ("bfd", "| restart-required |"),
        ("ebgp_requires_policy", "| restart-required |"),
    ] {
        let rows = reload_matrix_rows_for(&matrix, field);
        assert!(
            !rows.is_empty(),
            "no reload-matrix table row found for `{field}`"
        );
        for row in rows {
            assert!(
                row.contains(class_cell),
                "reload-matrix class drift: the row for `{field}` must be \
                 classed `{class_cell}` (load-bearing: it tells operators \
                 whether SIGHUP is enough). Row reads: {row}"
            );
        }
    }

    let cap_rows = reload_matrix_rows_for(&matrix, "gr_peer_restart_time_max");
    assert_eq!(
        cap_rows.len(),
        2,
        "the GR peer restart cap must have neighbor and peer-group rows"
    );
    assert!(
        cap_rows[0].contains("| live |"),
        "the neighbor cap is hot-applied in place: {}",
        cap_rows[0]
    );
    assert!(
        cap_rows[1].contains("| live |"),
        "an all-hot peer-group cap edit hot-applies to static and dynamic \
         members in place: {}",
        cap_rows[1]
    );

    // ADR-0113: the outbound maxima are hot-applied at field level, so a
    // maxima-only peer-group edit is an all-`live` change set and must not
    // be documented as a session reset on either row.
    for field in ["max_prefixes_out_ipv4", "max_prefixes_out_ipv6"] {
        let rows = reload_matrix_rows_for(&matrix, field);
        assert_eq!(
            rows.len(),
            2,
            "`{field}` must have neighbor and peer-group rows"
        );
        for row in rows {
            assert!(
                row.contains("| live |"),
                "an outbound maximum hot-applies in place on both the \
                 neighbor and the peer-group path: {row}"
            );
        }
        assert_eq!(
            config_field_impact(field).map(|(impact, _)| impact),
            Some(ConfigFieldImpact::HotApplied),
            "`{field}` must classify as hot-applied, or the maxima-only \
             peer-group edit falls back to the ADR-0081 reshape"
        );
    }

    // The predicate the peer-group apply path consults, driven directly:
    // a maxima-only group edit must take the in-place cohort path.
    let old_group = PeerGroupConfig {
        max_prefixes_out_ipv4: std::num::NonZeroU32::new(8),
        ..Default::default()
    };
    let new_group = PeerGroupConfig {
        max_prefixes_out_ipv4: std::num::NonZeroU32::new(64),
        ..old_group.clone()
    };
    assert!(
        peer_group_change_hot_applicable(&old_group, &new_group),
        "a peer-group outbound-maximum edit must hot-apply in place"
    );
}
