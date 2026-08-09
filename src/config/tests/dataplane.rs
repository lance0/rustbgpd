use super::*;

// ---------------------------------------------------------------------------
// ADR-0061 — general-purpose unicast Linux FIB config skeleton.
// ---------------------------------------------------------------------------

#[test]
fn fib_tables_default_empty() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.fib_tables.is_empty());
}

#[test]
fn fib_tables_parse_explicit_opt_in() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();

    assert_eq!(config.fib_tables.len(), 1);
    let table = &config.fib_tables[0];
    assert_eq!(table.name, "edge");
    assert_eq!(table.table_id, 1000);
    assert_eq!(table.metric, 200);
    assert_eq!(table.families, ["ipv4_unicast", "ipv6_unicast"]);
    assert!(table.allowed_peer_groups.is_empty());
    assert!(table.allowed_neighbors.is_empty());
    assert_eq!(table.max_routes, None);
}

#[test]
fn fib_tables_reject_reserved_table_ids() {
    for id in [0, 252, 253, 254, 255] {
        let toml = format!(
            r#"
{}

[[fib_tables]]
name = "edge"
table_id = {id}
metric = 200
"#,
            valid_toml()
        );
        let err = parse(&toml).unwrap_err();
        let ConfigError::InvalidFibTable { reason } = err else {
            panic!("expected InvalidFibTable for table {id}, got {err}");
        };
        assert!(
            reason.contains("reserved"),
            "expected reserved-table error for {id}, got {reason}"
        );
    }
}

#[test]
fn fib_tables_reject_duplicate_names_and_tables() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200

[[fib_tables]]
name = "edge"
table_id = 1001
metric = 200
"#,
        valid_toml()
    );
    assert!(matches!(
        parse(&toml),
        Err(ConfigError::InvalidFibTable { .. })
    ));

    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge-a"
table_id = 1000
metric = 200

[[fib_tables]]
name = "edge-b"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    assert!(matches!(
        parse(&toml),
        Err(ConfigError::InvalidFibTable { .. })
    ));
}

#[test]
fn fib_tables_reject_non_unicast_families() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_flowspec"]
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidFibTable { reason } = err else {
        panic!("expected InvalidFibTable, got {err}");
    };
    assert!(reason.contains("unsupported family"));
}

#[test]
fn fib_tables_parse_guardrails() {
    let toml = format!(
        r#"
{}

[peer_groups.transit]

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_unicast"]
allowed_peer_groups = ["transit"]
allowed_neighbors = ["198.51.100.1", "2001:db8::1"]
max_routes = 1000
maximum_paths = 4
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();
    let table = &config.fib_tables[0];

    assert_eq!(table.allowed_peer_groups, ["transit"]);
    assert_eq!(table.allowed_neighbors, ["198.51.100.1", "2001:db8::1"]);
    assert_eq!(table.max_routes, Some(1000));
    assert_eq!(table.maximum_paths, Some(4));
}

#[test]
fn fib_tables_maximum_paths_defaults_to_none() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.fib_tables[0].maximum_paths, None);
}

#[test]
fn multipath_relax_parses_and_defaults_false() {
    // ADR-0066 multipath-relax is a global best-path knob, default off.
    let base = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
"#;
    assert!(
        !parse(base).unwrap().global.multipath_relax,
        "multipath_relax defaults to false"
    );
    let on = base.replace(
        "listen_port = 179",
        "listen_port = 179\nmultipath_relax = true",
    );
    assert!(parse(&on).unwrap().global.multipath_relax);
}

#[test]
fn link_bandwidth_weighted_parses_and_defaults_false() {
    // ADR-0068 weighted multipath is a global best-path knob, default off.
    let base = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
"#;
    assert!(
        !parse(base).unwrap().global.link_bandwidth_weighted,
        "link_bandwidth_weighted defaults to false"
    );
    let on = base.replace(
        "listen_port = 179",
        "listen_port = 179\nlink_bandwidth_weighted = true",
    );
    assert!(parse(&on).unwrap().global.link_bandwidth_weighted);
}

#[test]
fn fib_tables_reject_invalid_guardrails() {
    let cases = [
        (
            r#"allowed_peer_groups = ["missing"]"#,
            "undefined peer_group",
        ),
        (
            r#"allowed_neighbors = ["not-an-ip"]"#,
            "invalid allowed_neighbors",
        ),
        (
            r#"allowed_neighbors = ["198.51.100.1", "198.51.100.1"]"#,
            "duplicate allowed_neighbors",
        ),
        (r"max_routes = 0", "max_routes must be greater than zero"),
        (
            r"maximum_paths = 0",
            "maximum_paths must be greater than zero",
        ),
        (r"maximum_paths = 9999", "exceeds the supported cap"),
        (
            r"maximum_paths_ebgp = 0",
            "maximum_paths_ebgp must be greater than zero",
        ),
        (
            r"maximum_paths_ibgp = 9999",
            "maximum_paths_ibgp 9999 exceeds the supported cap",
        ),
    ];

    for (line, expected) in cases {
        let toml = format!(
            r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
{line}
"#,
            valid_toml()
        );
        let err = parse(&toml).unwrap_err();
        let ConfigError::InvalidFibTable { reason } = err else {
            panic!("expected InvalidFibTable, got {err}");
        };
        assert!(
            reason.contains(expected),
            "expected {expected:?} in error, got {reason:?}"
        );
    }
}

#[test]
fn fib_tables_per_class_maximum_paths_round_trip() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
maximum_paths = 2
maximum_paths_ebgp = 4
maximum_paths_ibgp = 8
"#,
        valid_toml()
    );
    let t = &parse(&toml).unwrap().fib_tables[0];
    assert_eq!(t.maximum_paths, Some(2));
    assert_eq!(t.maximum_paths_ebgp, Some(4));
    assert_eq!(t.maximum_paths_ibgp, Some(8));
}

#[test]
fn fib_tables_reject_duplicate_allowed_peer_groups() {
    let toml = format!(
        r#"
{}

[peer_groups.transit]

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
allowed_peer_groups = ["transit", "transit"]
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidFibTable { reason } = err else {
        panic!("expected InvalidFibTable, got {err}");
    };
    assert!(
        reason.contains("duplicate allowed_peer_groups"),
        "unexpected error: {reason}"
    );
}

#[test]
fn bfd_profiles_parse_and_neighbor_reference() {
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"
min_tx_interval = 250
min_rx_interval = 250
multiplier = 4

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
bfd = {{ profile = "fast", strict = true }}
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.bfd_profiles.len(), 1);
    assert_eq!(config.bfd_profiles[0].min_tx_interval, 250);
    assert_eq!(config.bfd_profiles[0].multiplier, 4);
    let n = config
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.3")
        .unwrap();
    let bfd = n.bfd.as_ref().unwrap();
    assert_eq!(bfd.profile, "fast");
    assert!(bfd.strict);
}

#[test]
fn bfd_profile_defaults_are_300_300_3() {
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "p"
"#,
        valid_toml()
    );
    let p = &parse(&toml).unwrap().bfd_profiles[0];
    assert_eq!(
        (p.min_tx_interval, p.min_rx_interval, p.multiplier),
        (300, 300, 3)
    );
}

#[test]
fn bfd_rejects_invalid_profiles() {
    let cases = [
        ("name = \"p\"\nmin_tx_interval = 50", "must be >= 100"),
        ("name = \"p\"\nmultiplier = 1", "multiplier must be >= 2"),
        // Upper bounds: out-of-range values must be rejected, not silently
        // clamped by the actor's u8 / microsecond conversions.
        (
            "name = \"p\"\nmultiplier = 1000",
            "multiplier must be <= 255",
        ),
        ("name = \"p\"\nmin_rx_interval = 5000000", "must be <= "),
        (
            "name = \"dup\"\n\n[[bfd_profiles]]\nname = \"dup\"",
            "duplicate bfd_profile",
        ),
    ];
    for (body, expected) in cases {
        let toml = format!("{}\n\n[[bfd_profiles]]\n{body}\n", valid_toml());
        let err = parse(&toml).unwrap_err();
        let ConfigError::InvalidBfd { reason } = err else {
            panic!("expected InvalidBfd, got {err}");
        };
        assert!(
            reason.contains(expected),
            "expected {expected:?} in {reason:?}"
        );
    }
}

#[test]
fn bfd_rejects_undefined_profile_reference() {
    let toml = format!(
        r#"
{}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
bfd = {{ profile = "nope" }}
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidBfd { reason } = err else {
        panic!("expected InvalidBfd, got {err}");
    };
    assert!(reason.contains("not defined"), "unexpected: {reason}");
}

#[test]
fn fib_tables_diff_marks_reload_applied() {
    // N→M edit: a table already exists at startup (so the reconciler is live),
    // and the new config tweaks it. These hot-apply via SIGHUP / gRPC
    // (`FibRuntimeCommand::ReplaceTables`), so the static diff classifies them
    // reload-applied, not restart-required.
    let with_table = |metric: u32| {
        format!(
            r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = {metric}
"#,
            valid_toml()
        )
    };
    let old = parse(&with_table(200)).unwrap();
    let new = parse(&with_table(250)).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.fib_tables_changed);
    assert!(!diff.fib_tables_requires_restart);
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn fib_tables_diff_from_empty_marks_restart_required() {
    // 0→N: no tables at startup means the reconciler was never spawned, so
    // SIGHUP cannot hot-start it — `src/reload.rs` rejects this as
    // restart-required. The static diff knows the empty-startup case (even
    // though it can't predict a netlink spawn failure), so it must match the
    // runtime and classify 0→N restart-required, not reload-applied.
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

    assert!(diff.fib_tables_changed);
    assert!(diff.fib_tables_requires_restart);
    assert!(diff.has_restart_required_changes());
    assert!(!diff.has_reload_applied_changes());
}

#[test]
fn bfd_rejects_ipv6_link_local_neighbor() {
    // v1 ships IPv4 + IPv6 global only; link-local BFD is deferred to v1.1
    // even though BGP link-local peers now carry interface scope.
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[[neighbors]]
address = "fe80::1"
interface = "eth0"
remote_asn = 65003
bfd = {{ profile = "fast" }}
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidBfd { reason } = err else {
        panic!("expected InvalidBfd, got {err}");
    };
    assert!(reason.contains("link-local"), "unexpected: {reason}");
}

#[test]
fn bfd_link_local_rejected_via_peer_group_inheritance() {
    // Inheriting BFD from a peer-group must also be rejected on a link-local
    // neighbor — the effective config is what matters, not just the inline form.
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[[neighbors]]
address = "fe80::2"
interface = "eth0"
remote_asn = 65003
peer_group = "rrc"
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidBfd { reason } = err else {
        panic!("expected InvalidBfd, got {err}");
    };
    assert!(reason.contains("link-local"), "unexpected: {reason}");
}

#[test]
fn bfd_diff_marks_restart_required_and_pins() {
    let old = parse(valid_toml()).unwrap();
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"
min_tx_interval = 200
min_rx_interval = 200
multiplier = 3

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
bfd = {{ profile = "fast" }}
"#,
        valid_toml()
    );
    let new = parse(&toml).unwrap();

    // The effective BFD session set changed → restart-required + surfaced.
    let diff = diff_config(&old, &new);
    assert!(diff.bfd_changed);
    assert!(diff.has_restart_required_changes());

    // A SIGHUP reload pins the BFD config back to the live snapshot so the
    // persisted config does not silently advance past the running actor.
    let mut runtime = new.clone();
    assert!(super::pin_bfd_startup_only_runtime(&mut runtime, &old));
    assert!(runtime.bfd_profiles.is_empty(), "profiles pinned to live");
    let pinned_neighbor = runtime
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.3")
        .unwrap();
    assert!(
        pinned_neighbor.bfd.is_none(),
        "hot-added neighbor's bfd pinned off until restart"
    );
    // After pinning, a re-diff against the live snapshot shows no BFD drift.
    assert!(!diff_config(&old, &runtime).bfd_changed);
}

/// The effective BFD session set must survive peer-group *membership* changes,
/// not just raw `neighbor.bfd` edits — BFD can be inherited, so moving a
/// neighbor between groups (or in/out of a BFD-bearing one) changes its
/// effective session without touching `neighbor.bfd`. The pin must restore the
/// live effective attachment for an existing neighbor in all three shapes.
#[test]
fn bfd_pin_restores_effective_set_across_peer_group_membership_changes() {
    // Live config: neighbor 10.0.0.3 inherits BFD from peer-group `rrc`.
    let live = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[peer_groups.plain]
hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rrc"
"#,
        valid_toml()
    ))
    .unwrap();

    // Detach: move the neighbor to a non-BFD group. Effective BFD would drop to
    // None, but the actor still runs the session → pin must keep it.
    let detached = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[peer_groups.plain]
hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "plain"
"#,
        valid_toml()
    ))
    .unwrap();
    assert!(diff_config(&live, &detached).bfd_changed);
    let mut runtime = detached.clone();
    assert!(super::pin_bfd_startup_only_runtime(&mut runtime, &live));
    assert!(
        !diff_config(&live, &runtime).bfd_changed,
        "detach via peer-group membership must be pinned back to the live session"
    );

    // Attach: a neighbor with no BFD moves into the BFD group. The actor has no
    // session → pin must keep effective BFD off.
    let plain_live = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[peer_groups.plain]
hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "plain"
"#,
        valid_toml()
    ))
    .unwrap();
    let attached = live.clone(); // same file: neighbor in `rrc` (BFD) group
    assert!(diff_config(&plain_live, &attached).bfd_changed);
    let mut runtime = attached.clone();
    assert!(super::pin_bfd_startup_only_runtime(
        &mut runtime,
        &plain_live
    ));
    assert!(
        !diff_config(&plain_live, &runtime).bfd_changed,
        "attach via peer-group membership must be pinned off until restart"
    );
}

/// A neighbor *added* in the same reload that *inherits* BFD from a pre-existing
/// BFD peer-group has no live actor session; the pin must materialize a disabled
/// inline block so the runtime's effective set still matches the live actor
/// (the `BfdConfig.enabled` tri-state makes "inherit-but-off" expressible).
#[test]
fn bfd_pin_disables_inherited_bfd_on_newly_added_neighbor() {
    let live = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}
"#,
        valid_toml()
    ))
    .unwrap();
    // Candidate adds a brand-new neighbor into the BFD-bearing peer-group.
    let added = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[[neighbors]]
address = "10.0.0.9"
remote_asn = 65009
peer_group = "rrc"
"#,
        valid_toml()
    ))
    .unwrap();
    assert!(diff_config(&live, &added).bfd_changed);

    let mut runtime = added.clone();
    assert!(super::pin_bfd_startup_only_runtime(&mut runtime, &live));
    let pinned = runtime
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.9")
        .unwrap();
    assert_eq!(
        pinned.bfd.as_ref().map(|b| b.enabled),
        Some(false),
        "added neighbor's inherited BFD must be pinned to a disabled inline block"
    );
    assert!(
        !diff_config(&live, &runtime).bfd_changed,
        "after pinning, the added neighbor must contribute no effective session"
    );
}

#[test]
fn managed_netdevs_default_empty_and_resolve_stamps() {
    let config = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = true\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan200\"\nvni = 200\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vlan_uppers]]\nname = \"br100.10\"\nbridge = \"br100\"\nvlan = 10\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ))
    .unwrap();

    let table = config.resolve_managed_netdevs().unwrap();
    assert_eq!(table.owner_token(), Some("leaf-1"));
    let bridge = table.bridge("br100").unwrap();
    assert_eq!(bridge.name, "br100");
    assert!(bridge.vlan_filtering);
    assert_eq!(bridge.ownership_stamp, "rustbgpd:bridge:leaf-1:br100");
    let vxlan = table.vxlan("vxlan200").unwrap();
    assert_eq!(vxlan.name, "vxlan200");
    assert_eq!(vxlan.spec.vni, 200);
    assert_eq!(
        vxlan.spec.local_ip,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(vxlan.spec.dstport, 4789);
    assert_eq!(vxlan.spec.bridge, "br100");
    assert_eq!(vxlan.ownership_stamp, "rustbgpd:vxlan:leaf-1:vxlan200");
    let svd_vxlan = table.svd_vxlan("vxlan-svd").unwrap();
    assert_eq!(svd_vxlan.name, "vxlan-svd");
    assert_eq!(
        svd_vxlan.spec.local_ip,
        Some("10.0.0.1".parse::<std::net::IpAddr>().unwrap())
    );
    assert_eq!(svd_vxlan.spec.dstport, 4789);
    assert_eq!(svd_vxlan.spec.bridge, "br100");
    assert_eq!(svd_vxlan.spec.bindings.len(), 1);
    assert_eq!(svd_vxlan.spec.bindings[0].bridge_vlan, 10);
    assert_eq!(svd_vxlan.spec.bindings[0].vni, 100);
    assert_eq!(
        svd_vxlan.ownership_stamp,
        "rustbgpd:svd-vxlan:leaf-1:vxlan-svd"
    );
    let vlan_upper = table.vlan_upper("br100.10").unwrap();
    assert_eq!(vlan_upper.name, "br100.10");
    assert_eq!(vlan_upper.spec.bridge, "br100");
    assert_eq!(vlan_upper.spec.vlan, 10);
    assert_eq!(
        vlan_upper.ownership_stamp,
        "rustbgpd:vlan-upper:leaf-1:br100.10"
    );
    let vrf = table.vrf("vrf100").unwrap();
    assert_eq!(vrf.name, "vrf100");
    assert_eq!(vrf.spec.table_id, 5000);
    assert_eq!(vrf.ownership_stamp, "rustbgpd:vrf:leaf-1:vrf100");
    let l3vxlan = table.l3vxlan("l3vxlan100").unwrap();
    assert_eq!(l3vxlan.name, "l3vxlan100");
    assert_eq!(l3vxlan.spec.vni, 5000);
    assert_eq!(
        l3vxlan.spec.local_ip,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(l3vxlan.spec.dstport, 4789);
    assert_eq!(l3vxlan.spec.vrf, "vrf100");
    assert_eq!(
        l3vxlan.spec.router_mac,
        rustbgpd_wire::MacAddress::new([0x02, 0, 0, 0, 0, 1])
    );
    assert_eq!(
        l3vxlan.ownership_stamp,
        "rustbgpd:l3vxlan:leaf-1:l3vxlan100"
    );

    let owner_only = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n",
        valid_toml()
    ))
    .unwrap();
    let owner_only_table = owner_only.resolve_managed_netdevs().unwrap();
    assert_eq!(owner_only_table.owner_token(), Some("leaf-1"));
    assert!(
        !owner_only_table.is_empty(),
        "owner-only managed_netdevs config must still spawn the dataplane actor for cleanup"
    );

    let empty = parse(valid_toml()).unwrap();
    assert!(empty.resolve_managed_netdevs().unwrap().is_empty());
}

#[test]
fn managed_netdevs_reject_missing_owner_duplicate_and_invalid_names() {
    let missing_owner = parse(&format!(
        "{}\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        missing_owner,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let duplicate = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = false\n\n[[managed_netdevs.vxlans]]\nname = \"br100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        duplicate,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let invalid_owner = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf 1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = false\n",
        valid_toml()
    ));
    assert!(matches!(
        invalid_owner,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let invalid_name = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan 100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    match invalid_name {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must contain only ASCII"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid VXLAN name rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_unknown_fields() {
    let unknown_top_level = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\nunknown = true\n",
        valid_toml()
    ));
    assert!(matches!(unknown_top_level, Err(ConfigError::Parse(_))));

    let unknown_bridge_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = true\nmtu = 9000\n",
        valid_toml()
    ));
    assert!(matches!(unknown_bridge_field, Err(ConfigError::Parse(_))));

    let unknown_vxlan_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\nexternal = true\n",
        valid_toml()
    ));
    assert!(matches!(unknown_vxlan_field, Err(ConfigError::Parse(_))));

    let unknown_vrf_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\nmtu = 9000\n",
        valid_toml()
    ));
    assert!(matches!(unknown_vrf_field, Err(ConfigError::Parse(_))));

    let unknown_l3vxlan_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\nexternal = true\n",
        valid_toml()
    ));
    assert!(matches!(unknown_l3vxlan_field, Err(ConfigError::Parse(_))));

    let unknown_vlan_upper_field = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vlan_uppers]]\nname = \"br100.10\"\nbridge = \"br100\"\nvlan = 10\nprotocol = \"802.1ad\"\n",
        valid_toml()
    ));
    assert!(matches!(
        unknown_vlan_upper_field,
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn managed_netdevs_reject_invalid_vlan_upper_fields() {
    let candidate = |body: &str| parse(&format!("{}\n{body}", valid_toml()));

    let missing_instance = candidate(
        r#"[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.10"
bridge = "br100"
vlan = 10
"#,
    );
    match missing_instance {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("bridge_vlan"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected missing bridge_vlan binding rejection, got {other:?}"),
    }

    let duplicate_binding = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.10"
bridge = "br100"
vlan = 10

[[managed_netdevs.vlan_uppers]]
name = "br100.10b"
bridge = "br100"
vlan = 10
"#,
    );
    match duplicate_binding {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("duplicate"), "unexpected reason: {reason}");
        }
        other => panic!("expected duplicate VLAN upper binding rejection, got {other:?}"),
    }

    let zero_vlan = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.0"
bridge = "br100"
vlan = 0
"#,
    );
    assert!(matches!(
        zero_vlan,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));
}

#[test]
fn managed_netdevs_reject_invalid_vlan_upper_bindings_and_names() {
    let candidate = |body: &str| parse(&format!("{}\n{body}", valid_toml()));

    // vlan above the Linux upper bound: the range check fires before the
    // binding check, so no matching [[evpn_instances]] is needed.
    let vlan_too_high = candidate(
        r#"[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.95"
bridge = "br100"
vlan = 4095
"#,
    );
    match vlan_too_high {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("1..=4094"), "unexpected reason: {reason}");
        }
        other => panic!("expected out-of-range VLAN upper rejection, got {other:?}"),
    }

    // An in-range vlan whose (bridge, vlan) pair does not match any configured
    // EVI binding is rejected: a *wrong* binding, not merely a missing one.
    let mismatched_binding = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100.20"
bridge = "br100"
vlan = 20
"#,
    );
    match mismatched_binding {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must match a configured [[evpn_instances]]"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected mismatched EVI binding rejection, got {other:?}"),
    }

    // Names dedup across all managed-netdev classes: a bridge and a VLAN upper
    // sharing a name collide. Bridges validate before VLAN uppers, so the
    // collision is detected on the VLAN upper insert.
    let cross_class_duplicate_name = candidate(
        r#"[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br100"
bridge_vlan = 10

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.bridges]]
name = "shared0"
vlan_filtering = true

[[managed_netdevs.vlan_uppers]]
name = "shared0"
bridge = "br100"
vlan = 10
"#,
    );
    match cross_class_duplicate_name {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("duplicate"), "unexpected reason: {reason}");
        }
        other => panic!("expected cross-class duplicate name rejection, got {other:?}"),
    }

    // An invalid link name (a space is not an allowed ifname character) is
    // rejected by validate_managed_link_name.
    let invalid_name = candidate(
        r#"[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vlan_uppers]]
name = "br100 10"
bridge = "br100"
vlan = 10
"#,
    );
    match invalid_name {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must contain only ASCII"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid VLAN-upper name rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_invalid_vxlan_fields() {
    let invalid_vni = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 16777216\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        invalid_vni,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let invalid_dstport = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\ndstport = 0\nbridge = \"br100\"\n",
        valid_toml()
    ));
    assert!(matches!(
        invalid_dstport,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let learning_enabled = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\nlearning = true\n",
        valid_toml()
    ));
    assert!(matches!(
        learning_enabled,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));
}

#[test]
fn managed_netdevs_reject_duplicate_vxlan_vni() {
    let duplicate_vni = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan200\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br200\"\n",
        valid_toml()
    ));
    match duplicate_vni {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("duplicate vni"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected duplicate-vni rejection, got {other:?}"),
    }

    // Distinct VNIs on distinct names load cleanly.
    let distinct_vnis = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan200\"\nvni = 200\nlocal = \"10.0.0.1\"\nbridge = \"br200\"\n",
        valid_toml()
    ));
    assert!(distinct_vnis.is_ok(), "got {distinct_vnis:?}");
}

#[test]
fn managed_netdevs_reject_fixed_vxlan_vni_colliding_with_svd_binding() {
    let collision = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    match collision {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("fixed-VNI") && reason.contains("SVD"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected fixed-vxlan/svd VNI collision rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_svd_binding_same_vlan_conflicting_vnis() {
    let conflict = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[[evpn_instances]]\nvni = 200\nrd = \"10.0.0.100:200\"\nroute_targets = [\"65000:200\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ));
    match conflict {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("conflicting"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected SVD bridge_vlan VNI conflict rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_accept_svd_binding_distinct_vlans() {
    let config = parse(&format!(
        "{}\n[[evpn_instances]]\nvni = 100\nrd = \"10.0.0.100:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 10\n\n[[evpn_instances]]\nvni = 200\nrd = \"10.0.0.100:200\"\nroute_targets = [\"65000:200\"]\nlocal_vtep_ip = \"10.0.0.100\"\nbridge = \"br100\"\nbridge_vlan = 20\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.svd_vxlans]]\nname = \"vxlan-svd\"\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n",
        valid_toml()
    ))
    .unwrap();
    let table = config.resolve_managed_netdevs().unwrap();
    let svd_vxlan = table.svd_vxlan("vxlan-svd").unwrap();
    assert_eq!(svd_vxlan.spec.bindings.len(), 2);
    let mapped: std::collections::BTreeMap<u16, u32> = svd_vxlan
        .spec
        .bindings
        .iter()
        .map(|b| (b.bridge_vlan, b.vni))
        .collect();
    assert_eq!(mapped.get(&10), Some(&100));
    assert_eq!(mapped.get(&20), Some(&200));
}

#[test]
fn managed_netdevs_reject_invalid_vrf_and_l3vxlan_fields() {
    let zero_table = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 0\n",
        valid_toml()
    ));
    assert!(matches!(
        zero_table,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let duplicate_table = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n\n[[managed_netdevs.vrfs]]\nname = \"vrf200\"\ntable_id = 5000\n",
        valid_toml()
    ));
    assert!(matches!(
        duplicate_table,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let duplicate_l3_vni = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan200\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf200\"\nrouter_mac = \"02:00:00:00:00:02\"\n",
        valid_toml()
    ));
    assert!(matches!(
        duplicate_l3_vni,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let learning_enabled = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\nlearning = true\n",
        valid_toml()
    ));
    assert!(matches!(
        learning_enabled,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));

    let multicast_router_mac = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"01:00:5e:00:00:01\"\n",
        valid_toml()
    ));
    assert!(matches!(
        multicast_router_mac,
        Err(ConfigError::InvalidManagedNetdev { .. })
    ));
}

#[test]
fn managed_netdevs_reject_reserved_vrf_table_id() {
    for id in [252, 253, 254, 255] {
        let reserved = parse(&format!(
            "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = {id}\n",
            valid_toml()
        ));
        match reserved {
            Err(ConfigError::InvalidManagedNetdev { reason }) => {
                assert!(
                    reason.contains("reserved"),
                    "unexpected reason for table_id {id}: {reason}"
                );
            }
            other => panic!("expected reserved-table rejection for {id}, got {other:?}"),
        }
    }

    // A non-reserved table_id still loads.
    let ok = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n",
        valid_toml()
    ));
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_vrf_table_id_colliding_with_fib_table() {
    let collision = parse(&format!(
        "{}\n[[fib_tables]]\nname = \"edge\"\ntable_id = 5000\nmetric = 200\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n",
        valid_toml()
    ));
    match collision {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(reason.contains("fib_tables"), "unexpected reason: {reason}");
        }
        other => panic!("expected vrf/fib_tables collision rejection, got {other:?}"),
    }

    // Distinct table_ids load cleanly.
    let ok = parse(&format!(
        "{}\n[[fib_tables]]\nname = \"edge\"\ntable_id = 1000\nmetric = 200\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 5000\n",
        valid_toml()
    ));
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_l3vxlan_vni_colliding_with_vxlan_vni() {
    let collision = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 6000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ));
    match collision {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("L3VNI") && reason.contains("L2VNI"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected l3vxlan/vxlan VNI collision rejection, got {other:?}"),
    }

    // Distinct L2/L3 VNIs load cleanly.
    let ok = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf100\"\ntable_id = 6000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ));
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_l3vxlan_without_managed_vrf_reference() {
    let missing_vrf = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan100\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf100\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ));
    match missing_vrf {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("must reference a configured [[managed_netdevs.vrfs]] row"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected missing managed VRF reference rejection, got {other:?}"),
    }
}

#[test]
fn managed_netdevs_reject_ip_vrf_managed_identity_mismatch() {
    let candidate = |vrf_table_id: u32, l3vni: u32, l3_local: &str, router_mac: &str| {
        parse(&format!(
            r#"{}
[[evpn_ip_vrfs]]
name = "blue"
vni = 5000
rd = "10.0.0.1:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf100"
l3vxlan_device = "l3vxlan5000"
table_id = 5000

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vrfs]]
name = "vrf100"
table_id = {vrf_table_id}

[[managed_netdevs.l3vxlans]]
name = "l3vxlan5000"
vni = {l3vni}
local = "{l3_local}"
vrf = "vrf100"
router_mac = "{router_mac}"
"#,
            valid_toml()
        ))
    };

    for (case, result, expected) in [
        (
            "vrf table",
            candidate(5001, 5000, "10.0.0.1", "02:00:00:00:00:01"),
            "table_id",
        ),
        (
            "l3vni",
            candidate(5000, 5001, "10.0.0.1", "02:00:00:00:00:01"),
            "vni",
        ),
        (
            "local",
            candidate(5000, 5000, "10.0.0.2", "02:00:00:00:00:01"),
            "local",
        ),
        (
            "router_mac",
            candidate(5000, 5000, "10.0.0.1", "02:00:00:00:00:02"),
            "router_mac",
        ),
    ] {
        match result {
            Err(ConfigError::InvalidManagedNetdev { reason }) => {
                assert!(
                    reason.contains(expected),
                    "unexpected {case} reason: {reason}"
                );
            }
            other => panic!("expected {case} mismatch rejection, got {other:?}"),
        }
    }

    let ok = candidate(5000, 5000, "10.0.0.1", "02:00:00:00:00:01");
    assert!(ok.is_ok(), "got {ok:?}");
}

#[test]
fn managed_netdevs_reject_ip_vrf_l3vxlan_vrf_mismatch() {
    // Two managed VRFs; the IP-VRF expects `vrf-blue` but the managed
    // L3VXLAN it binds is enslaved to `vrf-green`. vni/local/router_mac
    // and the `vrf-blue` table_id all match the IP-VRF, so the only
    // remaining divergence is the VRF the L3VXLAN attaches to — without
    // this check the lifecycle enslaves to the wrong VRF and IP-VRF
    // readiness (master == vrf_device) can never reach Ready.
    let candidate = |l3vxlan_vrf: &str| {
        parse(&format!(
            r#"{}
[[evpn_ip_vrfs]]
name = "blue"
vni = 5000
rd = "10.0.0.1:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "l3vxlan5000"
table_id = 5000

[managed_netdevs]
owner_token = "leaf-1"

[[managed_netdevs.vrfs]]
name = "vrf-blue"
table_id = 5000

[[managed_netdevs.vrfs]]
name = "vrf-green"
table_id = 6000

[[managed_netdevs.l3vxlans]]
name = "l3vxlan5000"
vni = 5000
local = "10.0.0.1"
vrf = "{l3vxlan_vrf}"
router_mac = "02:00:00:00:00:01"
"#,
            valid_toml()
        ))
    };

    match candidate("vrf-green") {
        Err(ConfigError::InvalidManagedNetdev { reason }) => {
            assert!(
                reason.contains("vrf") && reason.contains("vrf_device"),
                "unexpected vrf-mismatch reason: {reason}"
            );
        }
        other => panic!("expected L3VXLAN vrf/vrf_device mismatch rejection, got {other:?}"),
    }

    let ok = candidate("vrf-blue");
    assert!(ok.is_ok(), "matching L3VXLAN vrf should load, got {ok:?}");
}

#[test]
fn managed_netdevs_valid_multi_class_config_loads() {
    let config = parse(&format!(
        "{}\n[[fib_tables]]\nname = \"edge\"\ntable_id = 1000\nmetric = 200\n\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = true\n\n[[managed_netdevs.vxlans]]\nname = \"vxlan100\"\nvni = 100\nlocal = \"10.0.0.1\"\nbridge = \"br100\"\n\n[[managed_netdevs.vrfs]]\nname = \"vrf-blue\"\ntable_id = 5000\n\n[[managed_netdevs.l3vxlans]]\nname = \"l3vxlan5000\"\nvni = 5000\nlocal = \"10.0.0.1\"\nvrf = \"vrf-blue\"\nrouter_mac = \"02:00:00:00:00:01\"\n",
        valid_toml()
    ))
    .expect("valid multi-class managed-netdev config should load");
    assert_eq!(config.managed_netdevs.bridges.len(), 1);
    assert_eq!(config.managed_netdevs.vxlans.len(), 1);
    assert_eq!(config.managed_netdevs.vrfs.len(), 1);
    assert_eq!(config.managed_netdevs.l3vxlans.len(), 1);
}

#[test]
fn managed_netdevs_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new = parse(&format!(
        "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n\n[[managed_netdevs.bridges]]\nname = \"br100\"\nvlan_filtering = false\n",
        valid_toml()
    ))
    .unwrap();

    let diff = diff_config(&old, &new);
    assert!(diff.managed_netdevs_changed);
    assert!(diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["managed_netdevs_changed"], true);
    let text = format_config_diff(&diff);
    assert!(text.contains("[managed_netdevs] changed"));
}
