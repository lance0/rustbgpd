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
recovery_delay_seconds = 7
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
    assert_eq!(config.ethernet_segments.len(), 0);
    assert_eq!(config.resolve_ethernet_segments().unwrap().len(), 0);
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
    assert_eq!(segments[0].df_preference, 32_767, "RFC 9785 §3 default");
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
recovery_delay_seconds = 5

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

    let bindings = config
        .resolve_es_link_bindings(&AutoLacpEsis::default())
        .unwrap();
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
    let bindings = config
        .resolve_es_link_bindings(&AutoLacpEsis::default())
        .unwrap();
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
recovery_delay_seconds = 5
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("recovery_delay_seconds") && msg.contains("interface"),
        "msg must explain the dependency: {msg}"
    );
}

/// Both spellings of the hold-off key publish the validator's `0..=3600`
/// bounds: the bound parses, one past it is rejected.
#[test]
fn ethernet_segment_rejects_recovery_delay_out_of_range() {
    let schema: serde_json::Value = serde_json::from_str(&config_json_schema()).unwrap();
    let properties = &schema["$defs"]["EthernetSegmentConfig"]["properties"];
    assert_eq!(properties["recovery_delay_seconds"].get("deprecated"), None);
    assert_eq!(properties["recovery_delay_secs"]["deprecated"], true);
    for key in ["recovery_delay_seconds", "recovery_delay_secs"] {
        assert_eq!(properties[key]["minimum"], 0, "{key} schema minimum");
        assert_eq!(properties[key]["maximum"], 3600, "{key} schema maximum");
        let segment = |value: u64| {
            evpn_toml_with(&format!(
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
{key} = {value}
"#
            ))
        };
        parse(&segment(3600)).unwrap_or_else(|e| panic!("{key} = 3600 is in range: {e}"));
        let err = parse(&segment(3601)).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, ConfigError::InvalidEthernetSegment { .. }),
            "expected InvalidEthernetSegment for {key}, got {msg}"
        );
        assert!(msg.contains("3601") && msg.contains("3600"), "{msg}");
    }
}

#[test]
fn ethernet_segment_accepts_legacy_recovery_delay_secs_spelling() {
    let segment = |key: &str| {
        evpn_toml_with(&format!(
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
{key} = 12
"#
        ))
    };
    let legacy = parse(&segment("recovery_delay_secs")).unwrap();
    let canonical = parse(&segment("recovery_delay_seconds")).unwrap();
    assert_eq!(legacy.ethernet_segments[0].recovery_delay_seconds, Some(12));
    assert_eq!(legacy.ethernet_segments, canonical.ethernet_segments);

    let both = segment("recovery_delay_secs = 12\nrecovery_delay_seconds");
    let err = parse(&both).unwrap_err().to_string();
    assert!(err.contains("duplicate field"), "{err}");
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
fn ethernet_segment_accepts_former_default_df_preference_for_modulo() {
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
df_preference = 32768
originator_ip = "10.0.0.100"
"#,
    );
    let segments = parse(&toml).unwrap().resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_preference, 32_768);
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
        msg.contains("32767") && msg.contains("32768"),
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

fn auto_lacp_toml(interface: Option<&str>, extra: &str) -> String {
    let binding = interface.map_or_else(String::new, |i| format!("interface = \"{i}\"\n"));
    evpn_toml_with(&format!(
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
esi = "auto-lacp"
member_vnis = [100]
originator_ip = "10.0.0.100"
{binding}{extra}"#
    ))
}

fn lacp_esi(last: u8) -> EthernetSegmentIdentifier {
    rustbgpd_evpn::lacp_type1_esi([0x02, 0x11, 0x22, 0x33, 0x44, last], 0x01c1)
}

/// Domain view of `config` through the readiness table `esis`.
fn auto_lacp_candidate(
    config: &Config,
    esis: &AutoLacpEsis,
) -> rustbgpd_evpn::EvpnRuntimeCandidate {
    rustbgpd_evpn::EvpnRuntimeCandidate::new(
        config.resolve_evpn_instances().unwrap(),
        config.resolve_evpn_ip_vrfs().unwrap(),
        config.resolve_ethernet_segments_with(esis).unwrap(),
    )
}

fn auto_lacp_model(config: &Config, esis: &AutoLacpEsis) -> rustbgpd_evpn::EvpnRuntimeModel {
    rustbgpd_evpn::EvpnRuntimeModel::startup(
        config.resolve_evpn_instances().unwrap(),
        config.resolve_evpn_ip_vrfs().unwrap(),
        config.resolve_ethernet_segments_with(esis).unwrap(),
    )
}

#[test]
fn ethernet_segment_auto_lacp_validates_without_a_bond_and_stays_not_ready() {
    // No kernel read at validation: a bond that does not exist on this
    // host (the `rustbgpd --check` off-box case) still validates, and
    // the segment resolves to nothing until the probe publishes an ESI.
    let config = parse(&auto_lacp_toml(Some("bond0"), "")).unwrap();
    let esis = AutoLacpEsis::default();
    assert_eq!(
        config.resolve_ethernet_segments_with(&esis).unwrap(),
        Vec::new()
    );
    assert_eq!(
        config.resolve_es_link_bindings(&esis).unwrap(),
        BTreeMap::new()
    );
    assert_eq!(
        config.auto_lacp_interfaces(),
        BTreeSet::from(["bond0".to_string()])
    );
}

#[test]
fn ethernet_segment_auto_lacp_resolves_the_published_esi_and_follows_changes() {
    let config = parse(&auto_lacp_toml(Some("bond0"), "")).unwrap();
    let esis = AutoLacpEsis::default();
    let not_ready = auto_lacp_model(&config, &esis);

    assert!(esis.replace(BTreeMap::from([("bond0".to_string(), lacp_esi(0x55))])));
    let segments = config.resolve_ethernet_segments_with(&esis).unwrap();
    assert_eq!(segments[0].esi, lacp_esi(0x55));
    let bindings = config.resolve_es_link_bindings(&esis).unwrap();
    assert_eq!(bindings[&lacp_esi(0x55)].interface, "bond0");
    // Validation resolves against an empty table.
    assert_eq!(config.resolve_ethernet_segments().unwrap(), Vec::new());
    // The spec, not the derived value, is what persists.
    assert_eq!(config.ethernet_segments[0].esi, "auto-lacp");
    let plan = not_ready.plan_candidate(&auto_lacp_candidate(&config, &esis));
    assert_eq!(plan.ethernet_segments.added, vec![lacp_esi(0x55)]);

    // CE replaced: the same config re-converges as delete old + add new.
    let model = auto_lacp_model(&config, &esis);
    assert!(esis.replace(BTreeMap::from([("bond0".to_string(), lacp_esi(0x66))])));
    let plan = model.plan_candidate(&auto_lacp_candidate(&config, &esis));
    assert_eq!(plan.ethernet_segments.deleted, vec![lacp_esi(0x55)]);
    assert_eq!(plan.ethernet_segments.added, vec![lacp_esi(0x66)]);

    // Partner lost: the segment is withdrawn.
    let model = auto_lacp_model(&config, &esis);
    assert!(esis.replace(BTreeMap::new()));
    let plan = model.plan_candidate(&auto_lacp_candidate(&config, &esis));
    assert_eq!(plan.ethernet_segments.deleted, vec![lacp_esi(0x66)]);
}

#[test]
fn ethernet_segment_auto_lacp_collision_stays_not_ready() {
    let explicit = lacp_esi(0x77);
    let extra = format!(
        r#"
[[ethernet_segments]]
esi = "{explicit}"
member_vnis = [200]
originator_ip = "10.0.0.100"
interface = "eth9"
"#
    );
    let config = parse(&auto_lacp_toml(Some("bond0"), &extra)).unwrap();
    let esis = AutoLacpEsis::default();
    esis.replace(BTreeMap::from([("bond0".to_string(), explicit)]));
    let segments = config.resolve_ethernet_segments_with(&esis).unwrap();
    assert_eq!(segments.len(), 1, "only the explicit segment resolves");
    assert_eq!(segments[0].member_vnis.len(), 1);
    assert_eq!(
        config.resolve_es_link_bindings(&esis).unwrap()[&explicit].interface,
        "eth9",
        "a colliding derived ESI must not steal the explicit binding"
    );
    assert_eq!(
        config.auto_lacp_collisions(&esis),
        BTreeSet::from(["bond0".to_string()])
    );
}

#[test]
fn ethernet_segment_auto_lacp_requires_interface() {
    let msg = parse(&auto_lacp_toml(None, "")).unwrap_err().to_string();
    assert!(
        msg.contains("auto-lacp") && msg.contains("requires `interface`"),
        "{msg}"
    );
}

#[test]
fn ethernet_segment_auto_lacp_shape_rules_apply_before_ready() {
    let shared_vni = r#"
[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#;
    let msg = parse(&auto_lacp_toml(Some("rbgp-shape0"), shared_vni))
        .unwrap_err()
        .to_string();
    assert!(msg.contains("multiple ethernet_segments"), "{msg}");

    let same_bond = r#"
[[ethernet_segments]]
esi = "auto-lacp"
member_vnis = [200]
originator_ip = "10.0.0.100"
interface = "rbgp-shape0"
"#;
    let msg = parse(&auto_lacp_toml(Some("rbgp-shape0"), same_bond))
        .unwrap_err()
        .to_string();
    assert!(msg.contains("one bond derives one ESI"), "{msg}");
}
