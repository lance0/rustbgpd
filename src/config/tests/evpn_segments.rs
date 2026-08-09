use super::*;

#[test]
fn ethernet_segment_add_diff_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new_toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.ethernet_segments_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn ethernet_segment_binding_only_diff_marks_reload_applied() {
    let old_toml = evpn_toml_with(
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
    );
    let new_toml = evpn_toml_with(
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
interface = "eth2"
recovery_delay_secs = 7
"#,
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.ethernet_segments_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

// ---------------------------------------------------------------------------
// ADR-0057 — Ethernet Segment config. Validates Gate 8's operator-facing
// `[[ethernet_segments]]` block before the daemon spawns the orchestrator.
// ---------------------------------------------------------------------------

#[test]
fn ethernet_segments_default_empty() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.ethernet_segments.is_empty());
    assert!(config.resolve_ethernet_segments().unwrap().is_empty());
}

#[test]
fn ethernet_segments_reject_member_vni_shared_across_segments() {
    // Gate 8b ESI-aware MAC origination keys on `(VNI -> ESI)`.
    // If two segments listed the same member VNI, the origination
    // path would silently pick whichever resolved first and emit
    // wrong-ESI Type 2 routes for MACs the operator actually
    // intended for the other segment. Reject at config load.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    );
    // Validation fires inside `Config::load` / `parse`, so the
    // error surfaces here before any caller can construct the
    // ambiguous segment table at runtime.
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("VNI 100") && msg.contains("multiple ethernet_segments"),
        "expected VNI-collision error, got: {msg}"
    );
}

#[test]
fn ethernet_segment_minimal_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].member_vnis.len(), 1);
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::DefaultModulo);
    assert_eq!(segments[0].df_preference, 32_768);
    assert_eq!(segments[0].redundancy_mode, RedundancyMode::AllActive);
}

#[test]
fn ethernet_segment_interface_binding_parses_and_resolves() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
interface = "bond0"
recovery_delay_secs = 5

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(
        segments.len(),
        2,
        "bindings must not leak into the domain type"
    );

    let bindings = config.resolve_es_link_bindings().unwrap();
    assert_eq!(
        bindings.len(),
        1,
        "only the bound segment resolves a binding"
    );
    let binding = bindings.get(&segments[0].esi).expect("bound ESI present");
    assert_eq!(binding.interface, "bond0");
    assert_eq!(binding.recovery_delay, std::time::Duration::from_secs(5));
    assert!(
        !bindings.contains_key(&segments[1].esi),
        "unbound segment has no binding entry"
    );
}

#[test]
fn ethernet_segment_recovery_delay_defaults_to_thirty_seconds() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
interface = "eth1"
"#,
    );
    let config = parse(&toml).unwrap();
    let bindings = config.resolve_es_link_bindings().unwrap();
    assert_eq!(
        bindings.values().next().unwrap().recovery_delay,
        std::time::Duration::from_secs(30),
        "ADR-0085 decision 3 default"
    );
}

#[test]
fn ethernet_segment_rejects_recovery_delay_without_interface() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
recovery_delay_secs = 5
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("recovery_delay_secs") && msg.contains("interface"),
        "msg must explain the dependency: {msg}"
    );
}

#[test]
fn ethernet_segment_rejects_recovery_delay_out_of_range() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
interface = "eth1"
recovery_delay_secs = 3601
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(msg.contains("3601") && msg.contains("3600"), "{msg}");
}

#[test]
fn ethernet_segment_rejects_empty_or_overlong_interface() {
    for (interface, needle) in [
        ("\"\"", "must not be empty"),
        ("\"a-name-longer-than-ifnamsiz\"", "IFNAMSIZ"),
    ] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
interface = {interface}
"#
        ));
        let err = parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, ConfigError::InvalidEthernetSegment { .. }),
            "expected InvalidEthernetSegment for {interface}, got {msg}"
        );
        assert!(msg.contains(needle), "{msg}");
    }
}

#[test]
fn ethernet_segment_rejects_empty_member_vnis() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = []
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("member_vnis"),
        "msg must call out member_vnis: {msg}"
    );
}

#[test]
fn ethernet_segment_accepts_highest_random_weight_df_algorithm() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "highest-random-weight"
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::HighestRandomWeight);
}

#[test]
fn ethernet_segment_accepts_highest_preference_df_algorithm() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "highest-preference"
df_preference = 100
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::HighestPreference);
    assert_eq!(segments[0].df_preference, 100);
}

#[test]
fn ethernet_segment_accepts_lowest_preference_df_algorithm() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "lowest-preference"
df_preference = 42
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::LowestPreference);
    assert_eq!(segments[0].df_preference, 42);
}

#[test]
fn ethernet_segment_accepts_df_dont_preempt_with_preference_algorithm() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "highest-preference"
df_preference = 100
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert!(segments[0].df_dont_preempt);
}

#[test]
fn ethernet_segment_rejects_df_dont_preempt_without_preference_algorithm() {
    // DP is meaningless for default-modulo (the default algorithm) — fail closed
    // rather than silently ignore it.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {err:?}"
    );
}

#[test]
fn ethernet_segment_rejects_df_dont_preempt_with_highest_random_weight() {
    // DP is meaningless for HRW too — only the preference algorithms carry it.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "highest-random-weight"
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {err:?}"
    );
}

#[test]
fn ethernet_segment_accepts_df_dont_preempt_with_lowest_preference() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "lowest-preference"
df_preference = 42
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::LowestPreference);
    assert!(segments[0].df_dont_preempt);
}

#[test]
fn ethernet_segment_rejects_ambiguous_preference_df_algorithm_alias() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "preference-based"
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("ambiguous RFC 9785 alias"),
        "msg must call out the ambiguous alias: {msg}"
    );
}

#[test]
fn ethernet_segment_accepts_single_active_redundancy_mode() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
redundancy_mode = "single-active"
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].redundancy_mode, RedundancyMode::SingleActive);
}

#[test]
fn ethernet_segment_rejects_unknown_redundancy_mode() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
redundancy_mode = "active-standby"
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("redundancy_mode"),
        "msg must call out redundancy_mode: {msg}"
    );
}

#[test]
fn ethernet_segment_rejects_non_default_df_preference() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_preference = 100
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("32768"),
        "msg must name supported preference: {msg}"
    );
}

#[test]
fn ethernet_segment_rejects_out_of_range_df_preference() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "highest-preference"
df_preference = 65536
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("0..=65535"),
        "msg must name the RFC 9785 preference range: {msg}"
    );
}
