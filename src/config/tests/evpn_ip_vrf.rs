use super::*;

#[test]
fn evpn_ip_vrf_add_diff_marks_reload_applied() {
    let old = parse(&evpn_toml_with("")).unwrap();
    let new_toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.evpn_ip_vrfs_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn evpn_ip_vrf_identity_redefine_diff_marks_restart_required() {
    let old_toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let new_toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5001
"#,
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_ip_vrfs_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::RestartRequired
    );
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

// ---------------------------------------------------------------------------
// EVPN Gate 9 — `[[evpn_ip_vrfs]]` schema, parse, validation. ADR-0058.
//
// These tests pin the operator-facing TOML surface for local IP-VRFs
// and the resolution into `IpVrfTable`. They cover the per-entry parse
// (name shape / VNI range / RD / RT / VTEP / Router MAC / device /
// table id), the table-level uniqueness checks, the L2↔L3 VNI overlap
// check, and the `[[evpn_instances]].ip_vrf` cross-reference.
// ---------------------------------------------------------------------------

#[test]
fn evpn_ip_vrfs_default_empty() {
    // No `[[evpn_ip_vrfs]]` block ⇒ L2-only VTEP / RR shape stays valid.
    let config = parse(valid_toml()).unwrap();
    assert!(config.evpn_ip_vrfs.is_empty());
    assert!(config.resolve_evpn_ip_vrfs().unwrap().is_empty());
}

#[test]
fn evpn_ip_vrf_minimal_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.evpn_ip_vrfs.len(), 1);
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    assert_eq!(table.len(), 1);
    let vrf = table.get("tenant-blue").unwrap();
    assert_eq!(vrf.id.as_u32(), 5000);
    assert_eq!(vrf.vrf_device, "vrf-blue");
    assert_eq!(vrf.l3vxlan_device, "vni5000");
    assert_eq!(vrf.table_id, 5000);
    assert_eq!(
        vrf.overlay_index_mode,
        rustbgpd_evpn::OverlayIndexMode::InterfaceLess,
        "omitted overlay_index_mode defaults to interface_less"
    );
}

#[test]
fn evpn_ip_vrf_gateway_ip_mode_requires_linked_l2vni() {
    // gateway_ip on an IP-VRF with no [[evpn_instances]].ip_vrf link
    // is rejected at load (ADR-0087 decision 3).
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "gateway_ip"
"#,
    );
    // `parse` runs full validation, which resolves the IP-VRF table
    // (validation.rs), so the rejection surfaces here.
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("gateway_ip") && msg.contains("ip_vrf"),
        "expected gateway_ip-without-linked-L2VNI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_gateway_ip_mode_with_linked_l2vni_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "gateway_ip"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    assert_eq!(
        table.get("tenant-blue").unwrap().overlay_index_mode,
        rustbgpd_evpn::OverlayIndexMode::GatewayIp,
    );
}

#[test]
fn evpn_ip_vrf_esi_mode_with_single_linked_segment_member_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    let vrf = table.get("tenant-blue").unwrap();
    assert_eq!(vrf.overlay_index_mode, rustbgpd_evpn::OverlayIndexMode::Esi);
    assert_eq!(
        vrf.overlay_index_esi.unwrap().octets(),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(
        vrf.overlay_index_mac.unwrap().octets(),
        [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
    );
    assert_eq!(vrf.overlay_index_l2vni, None);
}

#[test]
fn evpn_ip_vrf_esi_mode_requires_payload_fields() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "esi"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("overlay_index_esi"),
        "expected missing ESI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_fields_are_only_valid_in_esi_mode() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("only valid when overlay_index_mode = \"esi\""),
        "expected mode-gated field rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_mode_rejects_unknown_esi() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [100]
originator_ip = "10.0.0.100"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("does not match any configured") && msg.contains("ethernet_segments"),
        "expected unknown ESI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_mode_requires_l2vni_when_multiple_linked() {
    let toml = evpn_toml_with(
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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100, 200]
originator_ip = "10.0.0.100"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("multiple linked L2VNIs") && msg.contains("overlay_index_l2vni"),
        "expected ambiguous linked-L2VNI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_esi_mode_rejects_l2vni_outside_segment() {
    let toml = evpn_toml_with(
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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.100"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "esi"
overlay_index_esi = "00:00:00:00:00:00:00:00:00:01"
overlay_index_mac = "02:aa:bb:cc:dd:ee"
overlay_index_l2vni = 200
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not a member of overlay_index_esi"),
        "expected selected-L2VNI segment-membership rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_unknown_overlay_index_mode() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
overlay_index_mode = "asymmetric"
"#,
    );
    assert!(parse(&toml).is_err(), "unknown mode must fail to parse");
}

#[test]
fn evpn_ip_vrf_auto_derives_route_target() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    let vrf = table.get("tenant-blue").unwrap();
    // L3VNI / IP-VRF auto-RT is plain AS:VNI (matches FRR's default
    // tenant-VRF auto-RT), not the RFC 8365 opaque L2VNI form.
    assert_eq!(
        vrf.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:5000"]
    );
}

#[test]
fn evpn_ip_vrf_auto_derives_and_preserves_explicit_route_targets() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:9999"]
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    let vrf = table.get("tenant-blue").unwrap();
    // Explicit RT (65000:9999) and the derived AS:VNI RT (65000:5000)
    // both present; config resolution sorts the RT list.
    assert_eq!(
        vrf.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:5000", "65000:9999"]
    );
}

#[test]
fn evpn_ip_vrf_auto_derive_rejects_four_octet_asn() {
    let toml = r#"
[global]
asn = 4200000000
router_id = "10.0.0.100"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
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
fn evpn_ip_vrf_rejects_missing_route_targets_without_auto_derive() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnIpVrf { .. }),
        "got {msg}"
    );
    assert!(msg.contains("route_targets"));
}

#[test]
fn evpn_ip_vrf_rejects_l3vni_colliding_with_l2vni() {
    // L2VNI 100 declared, then [[evpn_ip_vrfs]] tries to reuse it as L3VNI.
    // Must be rejected at config-load time — the wire VNI space is shared.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 100
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni100"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("collides") && msg.contains("100"),
        "msg must call out the VNI collision: {msg}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_duplicate_name() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-blue-2"
l3vxlan_device = "vni5001"
table_id = 5001
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("duplicate name"),
        "msg must mention duplicate name: {err}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_bad_router_mac() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "01:00:5e:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("router_mac"),
        "msg must name the bad field: {err}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_bad_name_shape() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "1bad"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("name"),
        "msg must name the offending field: {err}"
    );
}

#[test]
fn evpn_instance_ip_vrf_link_must_resolve() {
    // An [[evpn_instances]] entry referencing an undeclared IP-VRF is
    // rejected at config-load time.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("ip_vrf"),
        "msg must mention ip_vrf reference: {err}"
    );
}

#[test]
fn evpn_instance_ip_vrf_link_marks_referenced() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-red"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-red"
l3vxlan_device = "vni5001"
table_id = 5001
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    assert_eq!(table.len(), 2);
    assert!(
        table.is_referenced("tenant-blue"),
        "tenant-blue is bound by [[evpn_instances]].ip_vrf"
    );
    let linked_vnis = table
        .referenced_l2vnis("tenant-blue")
        .expect("tenant-blue should carry linked L2VNI set");
    assert!(linked_vnis.contains(&rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()));
    assert!(
        !table.is_referenced("tenant-red"),
        "tenant-red has no L2VNI binding"
    );
    assert!(table.referenced_l2vnis("tenant-red").is_none());
}

#[test]
fn evpn_ip_vrf_validation_catches_errors_at_validate() {
    // Top-level `validate()` (called inside the test `parse` helper)
    // must surface IP-VRF errors so a malformed [[evpn_ip_vrfs]] block
    // doesn't slip past `Config::load`.
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "not a real rd"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("rd"),
        "validate() must surface the bad rd: {err}"
    );
}
