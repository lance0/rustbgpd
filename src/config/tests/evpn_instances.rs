use super::*;

#[test]
fn evpn_instances_default_empty() {
    // No `[[evpn_instances]]` block ⇒ empty list, valid config (RR mode).
    let config = parse(valid_toml()).unwrap();
    assert!(config.evpn_instances.is_empty());
    assert_eq!(config.resolve_evpn_instances().unwrap().len(), 0);
}

#[test]
fn evpn_instance_minimal_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.evpn_instances.len(), 1);
    let table = config.resolve_evpn_instances().unwrap();
    assert_eq!(table.len(), 1);
    let inst = table.sorted()[0];
    assert_eq!(inst.id.as_u32(), 100);
    assert_eq!(inst.route_targets.len(), 1);
    assert!(!inst.advertise_svi_mac);
    assert!(inst.bridge.is_none());
}

#[test]
fn evpn_instance_auto_derives_route_target() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.sorted()[0];
    assert_eq!(
        inst.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:268435556"]
    );
}

#[test]
fn evpn_instance_auto_derives_and_preserves_explicit_route_targets() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100", "65000:268435556"]
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.sorted()[0];
    assert_eq!(
        inst.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:100", "65000:268435556"],
        "explicit RTs are preserved and the derived RT is deduped"
    );
}

#[test]
fn evpn_instance_auto_derive_rejects_four_octet_asn() {
    let toml = r#"
[global]
asn = 4200000000
router_id = "10.0.0.100"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
"#;
    let err = parse(toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("auto_derive_route_target")
            && msg.contains("2-octet AS")
            && msg.contains("route_targets manually"),
        "msg must explain the 4-octet ASN limitation: {msg}"
    );
}

#[test]
fn evpn_instance_full_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200", "65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br200"
bridge_vlan = 20
advertise_svi_mac = true
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.sorted()[0];
    assert_eq!(inst.id.as_u32(), 200);
    assert_eq!(inst.bridge.as_deref(), Some("br200"));
    assert_eq!(inst.bridge_vlan.unwrap().as_u32(), 20);
    assert!(inst.advertise_svi_mac);
    // RTs are sorted/deduped on construction.
    assert_eq!(inst.route_targets.len(), 2);
}

#[test]
fn evpn_instance_rejects_unknown_field() {
    // `deny_unknown_fields` — typos must surface, not silently drop.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
oops_typo = true
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::Parse(_)),
        "expected toml parse error, got {err}"
    );
}

#[test]
fn evpn_instance_rejects_zero_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 0
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "expected InvalidEvpnInstance, got {msg}",
    );
    assert!(msg.contains("VNI 0"), "msg must explain why: {msg}");
}

#[test]
fn evpn_instance_rejects_overflow_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 16777216
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("24-bit"));
}

#[test]
fn evpn_instance_accepts_max_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 16777215
rd = "10.0.0.100:1"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    parse(&toml).unwrap();
}

#[test]
fn evpn_instance_rejects_invalid_rd() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "not-a-real-rd"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("rd"));
}

#[test]
fn evpn_instance_rejects_empty_route_targets() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = []
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {msg}"
    );
    assert!(msg.contains("route_targets"));
}

#[test]
fn evpn_instance_rejects_missing_route_targets_without_auto_derive() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {msg}"
    );
    assert!(msg.contains("route_targets"));
}

#[test]
fn evpn_instance_rejects_invalid_route_target() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["not-an-rt"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("route_target"));
}

#[test]
fn evpn_instance_rejects_non_unicast_vtep_ip() {
    for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "::", "::1"] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "{bad}"
"#
        ));
        let err = parse(&toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidEvpnInstance { .. }),
            "expected InvalidEvpnInstance for {bad}, got {err}",
        );
    }
}

#[test]
fn evpn_instance_rejects_unparseable_vtep_ip() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "not-an-ip"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("local_vtep_ip"));
}

#[test]
fn evpn_instance_rejects_empty_bridge() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "   "
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("bridge"));
}

#[test]
fn evpn_instance_bridge_vlan_accepts_bounds() {
    for vlan in [1, 4094] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = {vlan}
rd = "10.0.0.100:{vlan}"
route_targets = ["65000:{vlan}"]
local_vtep_ip = "10.0.0.100"
bridge = "br{vlan}"
bridge_vlan = {vlan}
"#
        ));
        let config = parse(&toml).unwrap();
        let table = config.resolve_evpn_instances().unwrap();
        let inst = table.get(EvpnInstanceId::new(vlan).unwrap()).unwrap();
        let bridge = format!("br{vlan}");
        assert_eq!(inst.bridge.as_deref(), Some(bridge.as_str()));
        assert_eq!(inst.bridge_vlan.unwrap().as_u32(), vlan);
    }
}

#[test]
fn evpn_instance_bridge_vlan_requires_bridge() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge_vlan = 10
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(
        err.to_string().contains("bridge_vlan requires bridge"),
        "got {err}"
    );
}

#[test]
fn evpn_instance_bridge_vlan_rejects_out_of_range() {
    for bad in [0, 4095, 70_000] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = {bad}
"#
        ));
        let err = parse(&toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidEvpnInstance { .. }),
            "expected InvalidEvpnInstance for bridge_vlan={bad}, got {err}"
        );
        assert!(
            err.to_string().contains("bridge_vlan must be in 1..=4094"),
            "unexpected message for bridge_vlan={bad}: {err}"
        );
    }
}

#[test]
fn evpn_instance_rejects_duplicate_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 100
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {msg}"
    );
    assert!(msg.contains("duplicate VNI"), "msg: {msg}");
}

#[test]
fn evpn_instance_rejects_duplicate_rd() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:100"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {msg}"
    );
    assert!(msg.contains("duplicate route distinguisher"), "msg: {msg}");
}

#[test]
fn evpn_instances_resolve_in_declaration_order_for_first_error() {
    // First entry is fine; second has a bad RT. The error should
    // identify the second entry, not the first.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["bad-rt"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("vni 200"), "msg: {msg}");
}

#[test]
fn evpn_instance_multiple_distinct_instances_resolve_cleanly() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300", "65000:301"]
local_vtep_ip = "10.0.0.100"
bridge = "br300"
advertise_svi_mac = true
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    assert_eq!(table.len(), 3);
    let sorted: Vec<u32> = table.sorted().iter().map(|i| i.id.as_u32()).collect();
    assert_eq!(sorted, vec![100, 200, 300]);

    // Spot-check display shape on the most-loaded entry.
    let inst300 = table.get(EvpnInstanceId::new(300).unwrap()).unwrap();
    let s = inst300.to_string();
    assert!(
        s.contains("vni=300")
            && s.contains("rd=10.0.0.100:300")
            && s.contains("bridge=br300")
            && s.contains("advertise-svi-mac"),
        "display surface broke: {s}",
    );
}

#[test]
fn evpn_instance_single_add_diff_marks_reload_applied() {
    let without_evi = parse(&evpn_toml_with("")).unwrap();
    let with_evi = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();

    let added = diff_config(&without_evi, &with_evi);
    assert!(added.evpn_instances_changed);
    assert_eq!(
        added.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(added.has_reload_applied_changes());
    assert!(!added.has_restart_required_changes());

    let removed = diff_config(&with_evi, &without_evi);
    assert!(removed.evpn_instances_changed);
    assert_eq!(
        removed.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(removed.has_reload_applied_changes());
    assert!(!removed.has_restart_required_changes());

    let json = config_diff_json_value(&added);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["reload_applied"]["evpn_instances_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
    let text = format_config_diff(&added);
    assert!(
        text.contains("EVPN runtime model hot-applied through the ADR-0063 coordinator"),
        "expected EVPN runtime reload-applied text, got:\n{text}"
    );
    assert!(
        !text.contains("[[evpn_instances]] changed"),
        "supported EVPN runtime shape must not be listed as restart-required:\n{text}"
    );

    // No-op: same config on both sides ⇒ not flagged.
    let same = diff_config(&with_evi, &with_evi);
    assert!(!same.evpn_instances_changed);
    assert_eq!(
        same.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::Unchanged
    );
}

#[test]
fn evpn_instance_standalone_swap_diff_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_bridge_vlan_redefine_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10
"#,
    ))
    .unwrap();

    let diff = diff_config(&old, &new);
    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn evpn_instance_swap_with_es_member_delete_decomposes_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert!(diff.ethernet_segments_changed);
    // #268: the ES-member delete decomposes into an atomic-teardown step
    // (L2VNI 100 + its ES) followed by the L2VNI 300 add step.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 2 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn evpn_instance_add_existing_es_member_expansion_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100, 200]
originator_ip = "10.0.0.100"
"#,
    ))
    .unwrap();

    let diff = diff_config(&old, &new);
    assert!(diff.evpn_instances_changed);
    assert!(diff.ethernet_segments_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_add_existing_es_field_change_decomposes_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100, 200]
originator_ip = "10.0.0.101"
"#,
    ))
    .unwrap();

    let diff = diff_config(&old, &new);
    assert!(diff.evpn_instances_changed);
    assert!(diff.ethernet_segments_changed);
    // #268: the ES field change + add-only build-up decomposes into an ES
    // redefine step followed by the add step, each its own generation.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 2 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn evpn_instance_swap_with_ip_vrf_link_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_mixed_redefine_swap_with_ip_vrf_link_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_multi_redefine_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:222"
route_targets = ["65000:222"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_multi_redefine_relink_decomposes_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:222"
route_targets = ["65000:222"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    // #268: decomposes into a batch L2VNI redefine step and a pure relink step.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 2 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(
        json["evpn_runtime_change_class"]["reload_applied_decomposed"]["steps"],
        2
    );
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_mixed_redefine_relink_decomposes_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    // #268: decomposes into deletes, L2VNI redefine, relink, and add steps.
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: 4 }
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(
        json["evpn_runtime_change_class"]["reload_applied_decomposed"]["steps"],
        4
    );
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_linked_swap_with_ip_vrf_identity_change_stays_restart_required() {
    // A linked L2VNI swap hot-applies, but only when the referenced IP-VRF
    // *row* is unchanged. Pin the boundary this slice moved: a swap that also
    // flips an IP-VRF identity field (here table_id) must fail closed to
    // restart-required, never riding the reload-applied swap path.
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5001
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::RestartRequired
    );
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "restart_required");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], false);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], true);
}

#[test]
fn evpn_instance_ipv6_vtep_accepted() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "2001:db8::1"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(
        inst.local_vtep_ip,
        std::net::IpAddr::V6("2001:db8::1".parse().unwrap())
    );
}

// ---------------------------------------------------------------------------
// ADR-0056 — sticky_macs schema. Validates parse, dedupe, and the
// restart-required diff path.
// ---------------------------------------------------------------------------

#[test]
fn evpn_sticky_macs_default_empty() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert!(inst.sticky_macs.is_empty());
}

#[test]
fn evpn_sticky_macs_round_trip() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(inst.sticky_macs.len(), 2);
    let want_a = rustbgpd_wire::MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    let want_b = rustbgpd_wire::MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
    assert!(inst.sticky_macs.contains(&want_a));
    assert!(inst.sticky_macs.contains(&want_b));
}

#[test]
fn evpn_sticky_macs_rejects_malformed() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["not-a-mac"]
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "expected InvalidEvpnInstance, got {msg}"
    );
    assert!(msg.contains("sticky_mac"), "msg must explain why: {msg}");
}

#[test]
fn evpn_sticky_macs_rejects_duplicate_within_instance() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:01"]
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "expected InvalidEvpnInstance, got {msg}"
    );
    assert!(
        msg.to_lowercase().contains("duplicate"),
        "msg must call out duplicate: {msg}"
    );
}

#[test]
fn evpn_sticky_macs_diff_marks_reload_applied() {
    // Adding sticky_macs to an existing instance is a single L2VNI
    // redefine. The ADR-0063 runtime coordinator can reconfigure that
    // shape live, so `--diff` must not leave it in the old
    // restart-required bucket.
    let base = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let with_sticky = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["aa:bb:cc:dd:ee:01"]
"#,
    );
    let old = parse(&base).unwrap();
    let new = parse(&with_sticky).unwrap();
    let diff = diff_config(&old, &new);
    assert!(
        diff.evpn_instances_changed,
        "adding sticky_macs must flip evpn_instances_changed"
    );
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

// ---------------------------------------------------------------------------
// RFC 7432 §15.1 — duplicate MAC detection / local suppression schema.
// ---------------------------------------------------------------------------

#[test]
fn evpn_duplicate_mac_detection_defaults_detect_only() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(
        inst.duplicate_mac_detection.action,
        rustbgpd_evpn::DuplicateMacAction::DetectOnly
    );
    assert_eq!(
        inst.duplicate_mac_detection.window,
        std::time::Duration::from_mins(3)
    );
    assert_eq!(inst.duplicate_mac_detection.threshold, 5);
    assert_eq!(
        inst.duplicate_mac_detection.recovery,
        std::time::Duration::from_mins(9)
    );
}

#[test]
fn evpn_duplicate_mac_detection_round_trip_suppress_local() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
duplicate_mac_detection = { action = "suppress_local", window_seconds = 30, threshold = 2, recovery_seconds = 90 }
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(
        inst.duplicate_mac_detection.action,
        rustbgpd_evpn::DuplicateMacAction::SuppressLocal
    );
    assert_eq!(
        inst.duplicate_mac_detection.window,
        std::time::Duration::from_secs(30)
    );
    assert_eq!(inst.duplicate_mac_detection.threshold, 2);
    assert_eq!(
        inst.duplicate_mac_detection.recovery,
        std::time::Duration::from_secs(90)
    );
}

#[test]
fn evpn_duplicate_mac_detection_rejects_invalid_values() {
    for (field, value) in [
        ("window_seconds", "0"),
        ("threshold", "0"),
        ("recovery_seconds", "0"),
        ("recovery_seconds", "31536001"),
    ] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
duplicate_mac_detection = {{ {field} = {value} }}
"#
        ));
        let err = parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, ConfigError::InvalidEvpnInstance { .. }),
            "expected InvalidEvpnInstance for {field}, got {msg}"
        );
        assert!(msg.contains(field), "message should name {field}: {msg}");
    }
}

#[test]
fn evpn_duplicate_mac_detection_diff_marks_reload_applied() {
    let base = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let suppress = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
duplicate_mac_detection = { action = "suppress_local" }
"#,
    );
    let old = parse(&base).unwrap();
    let new = parse(&suppress).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn apply_bum_enforcement_default_is_true() {
    // Pinned by the v0.23.0 production-default flip after the
    // Gate 8b 24h MAC-churn soak (2026-05-16, postmortem
    // `docs/soaks/soak-gate8b-mac-churn-24h.md`) and the M37
    // local-origination 24h soak (2026-05-19, postmortem
    // `docs/soaks/soak-m37-local-origination-churn-24h.md`) both passed
    // clean. If this regresses to `false` without a deliberate
    // schema change, the production posture has silently rolled back.
    let config = parse(valid_toml()).unwrap();
    assert!(
        config.apply_bum_enforcement,
        "apply_bum_enforcement default flipped to true in v0.23.0; \
         regression would silently restore observe-only behavior"
    );
}

#[test]
fn apply_bum_enforcement_honors_explicit_false() {
    // Operators who need the prior observe-only posture must still
    // be able to opt out explicitly after the default flip.
    let toml = format!("apply_bum_enforcement = false\n{}", valid_toml());
    let config = parse(&toml).unwrap();
    assert!(
        !config.apply_bum_enforcement,
        "explicit `apply_bum_enforcement = false` must be honored \
         after the v0.23.0 default flip"
    );
}

#[test]
fn apply_bum_enforcement_diff_marks_restart_required() {
    // Default is now true, so the diff has to be driven by an
    // explicit opt-out on the new side.
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!("apply_bum_enforcement = false\n{}", valid_toml());
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.apply_bum_enforcement_changed);
    assert!(diff.has_restart_required_changes());
}
