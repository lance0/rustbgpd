use super::*;

#[test]
fn dynamic_neighbor_effective_mode_validation_matrix() {
    // Load-bearing: removing the dynamic shared-validator call makes every
    // invalid inherited mode below load successfully and turns this test red.
    let rr = "route_reflector_client = true";
    let orr = "orr_vantage = \"192.0.2.7\"";
    let rr_router = "route_reflector_client = true\norr_vantage = \"10.0.0.1\"";
    let rr_unspecified = "route_reflector_client = true\norr_vantage = \"0.0.0.0\"";
    let rr_loopback = "route_reflector_client = true\norr_vantage = \"127.0.0.1\"";
    let cases = [
        (rr, 65002, "route_reflector_client requires iBGP"),
        (rr, 0, "route_reflector_client requires iBGP"),
        (orr, 65002, "orr_vantage requires iBGP"),
        (orr, 65001, "requires route_reflector_client = true"),
        (rr_router, 65001, "router_id"),
        (rr_unspecified, 65001, "unspecified or loopback"),
        (rr_loopback, 65001, "unspecified or loopback"),
        ("route_server_client = true", 65001, "requires eBGP"),
        (
            "per_client_best = true",
            65002,
            "per_client_best on neighbor",
        ),
        (
            "next_hop_ownership = \"strict_peer\"",
            65002,
            "next_hop_ownership",
        ),
        ("role = \"peer\"", 65001, "BGP Roles require eBGP"),
        ("strict_role = true", 65002, "strict_role requires role"),
    ];
    for (group_fields, remote_asn, expected) in cases {
        let err = parse(&dynamic_modes_toml(group_fields, remote_asn)).unwrap_err();
        let ConfigError::InvalidDynamicNeighbor { reason } = err else {
            panic!("expected dynamic rejection for {group_fields:?}, got {err}");
        };
        assert!(reason.contains("dynamic_neighbors[0] prefix \"10.0.0.0/24\""));
        assert!(reason.contains("peer_group \"modes\""));
        assert!(reason.contains(expected), "{group_fields:?}: {reason}");
    }
}

#[test]
fn valid_dynamic_peer_modes_resolve_cluster_and_transport() {
    // Load-bearing: removing the dynamic cluster scan loses both cluster
    // assertions; treating wildcard ASN 0 as iBGP or dropping group inheritance
    // breaks the valid route-server controls and resolved transport tuple.
    let rr = parse(&dynamic_modes_toml(
        "route_reflector_client = true\norr_vantage = \"192.0.2.7\"",
        65001,
    ))
    .unwrap();
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(rr.cluster_id(), cluster_id);
    let rr_resolved = resolve_dynamic_modes(&rr, 65001);
    assert_eq!(
        (
            rr_resolved.transport_config.route_reflector_client,
            rr_resolved.transport_config.orr_vantage,
            rr_resolved.transport_config.cluster_id,
        ),
        (true, Some("192.0.2.7".parse().unwrap()), cluster_id)
    );

    let rs_fields = "route_server_client = true\nper_client_best = true\n\
                     next_hop_ownership = \"strict_peer\"\nrole = \"route_server\"\n\
                     strict_role = true";
    for (configured_asn, accepted_asn) in [(65002, 65002), (0, 65003)] {
        let rs = parse(&dynamic_modes_toml(rs_fields, configured_asn)).unwrap();
        let resolved = resolve_dynamic_modes(&rs, accepted_asn);
        assert_eq!(
            (
                resolved.transport_config.route_server_client,
                resolved.transport_config.per_client_best,
                resolved.transport_config.next_hop_ownership_strict_peer,
                resolved.transport_config.peer.local_role,
                resolved.transport_config.peer.strict_role,
            ),
            (true, true, true, Some(BgpRole::RouteServer), true)
        );
    }
    assert_eq!(
        parse(&dynamic_modes_toml("", 0)).unwrap().cluster_id(),
        None
    );
}

#[test]
fn dynamic_neighbor_parses() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
remote_asn = 0
description = "IXP auto-accept"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(config.dynamic_neighbors.len(), 1);
    assert_eq!(config.dynamic_neighbors[0].prefix, "10.0.0.0/24");
    assert_eq!(config.dynamic_neighbors[0].peer_group, "ix-members");
    assert_eq!(config.dynamic_neighbors[0].remote_asn, 0);
}

#[test]
fn dynamic_neighbor_tcp_ao_parses_directly_and_redacts_debug() {
    let config = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "dynamic-secret", send_id = 7, recv_id = 9, algorithm = "hmac(sha256)" }
"#,
    ))
    .unwrap();
    let tcp_ao = config.dynamic_neighbors[0].tcp_ao.as_ref().unwrap();
    let tcp_ao = &tcp_ao.0[0];
    assert_eq!(tcp_ao.send_id, 7);
    assert_eq!(tcp_ao.recv_id, 9);
    let rendered = format!("{tcp_ao:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("dynamic-secret"));
}

#[test]
fn dynamic_neighbor_tcp_ao_rejects_overlapping_dynamic_auth_boundaries() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }

[[dynamic_neighbors]]
prefix = "10.0.0.128/25"
peer_group = "ix-members"
"#,
    ))
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("TCP-AO and non-TCP-AO authentication boundary")
    );
}

#[test]
fn dynamic_neighbor_tcp_ao_rejects_static_peer_inside_prefix() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "2001:db8::/32"
peer_group = "ix-members"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "2001:db8::42"
remote_asn = 65002
"#,
    ))
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("TCP-AO and non-TCP-AO authentication boundary")
    );
}

#[test]
fn md5_dynamic_range_rejects_plaintext_static_neighbor_inside_prefix() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[peer_groups.md5-members]
md5_password = "range-secret"

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "md5-members"

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
"#,
    ))
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("has no md5_password: the kernel's prefix key would require a signature"),
        "unexpected error: {err}"
    );

    // The same shape with a password on the inside neighbor is accepted: the
    // kernel resolves the host key by longest prefix match.
    parse(&dynamic_tcp_ao_toml(
        r#"
[peer_groups.md5-members]
md5_password = "range-secret"

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "md5-members"

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
md5_password = "host-secret"
"#,
    ))
    .unwrap();
}

#[test]
fn md5_dynamic_range_rejects_nested_plaintext_dynamic_range() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[peer_groups.md5-members]
md5_password = "range-secret"

[[dynamic_neighbors]]
prefix = "10.0.0.0/16"
peer_group = "md5-members"

[[dynamic_neighbors]]
prefix = "10.0.7.0/24"
peer_group = "ix-members"
"#,
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("nests inside MD5-protected"),
        "unexpected error: {err}"
    );

    // The inverse nesting is consistent: the more specific MD5 range wins
    // both the accept-time group match and the kernel key lookup.
    parse(&dynamic_tcp_ao_toml(
        r#"
[peer_groups.md5-members]
md5_password = "range-secret"

[[dynamic_neighbors]]
prefix = "10.0.0.0/16"
peer_group = "ix-members"

[[dynamic_neighbors]]
prefix = "10.0.7.0/24"
peer_group = "md5-members"
"#,
    ))
    .unwrap();
}

#[test]
fn overlapping_tcp_ao_owners_require_directionally_disjoint_ids() {
    let allowed = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "covering", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[dynamic_neighbors]]
prefix = "10.0.0.128/25"
peer_group = "ix-members"
tcp_ao = { key = "specific", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    );
    parse(&allowed).expect("disjoint directional IDs permit overlapping AO owners");

    for (send_id, recv_id, expected) in [(1, 12, "SendID"), (2, 11, "RecvID")] {
        let candidate = allowed.replace(
            "send_id = 2, recv_id = 12",
            &format!("send_id = {send_id}, recv_id = {recv_id}"),
        );
        let err = parse(&candidate).unwrap_err().to_string();
        assert!(err.contains(expected), "{err}");
        assert!(err.contains("disjoint SendID and RecvID"), "{err}");
    }
}

#[test]
fn overlapping_static_exact_and_dynamic_tcp_ao_requires_disjoint_ids() {
    let source = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
tcp_ao = { key = "exact", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    );
    parse(&source).expect("static exact AO may overlap with disjoint IDs");

    let err = parse(&source.replace("send_id = 2", "send_id = 1"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("SendID"), "{err}");
}

#[test]
fn overlapping_ipv6_tcp_ao_owners_follow_the_same_directional_id_rules() {
    let source = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "2001:db8::/64"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "2001:db8::42"
remote_asn = 65002
tcp_ao = { key = "exact", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    );
    parse(&source).expect("IPv6 static and dynamic AO owners may overlap with disjoint IDs");

    let err = parse(&source.replace("recv_id = 12", "recv_id = 11"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("RecvID"), "{err}");
}

#[test]
fn tcp_ao_overlap_with_static_inherited_md5_fails_closed() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[peer_groups.legacy]
md5_password = "legacy"

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.42"
peer_group = "legacy"
remote_asn = 65002
"#,
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("TCP-AO and non-TCP-AO authentication boundary"),
        "{err}"
    );
}

#[test]
fn tcp_ao_overlap_with_static_md5_fails_closed() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "range", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
md5_password = "legacy"
"#,
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("TCP-AO and non-TCP-AO authentication boundary"),
        "{err}"
    );
}

#[test]
fn plaintext_dynamic_overlap_with_static_tcp_ao_fails_closed() {
    let err = parse(&dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"

[[neighbors]]
address = "10.0.0.42"
remote_asn = 65002
tcp_ao = { key = "exact", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
"#,
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("TCP-AO and non-TCP-AO authentication boundary"),
        "{err}"
    );
}

#[test]
fn dynamic_neighbor_tcp_ao_rejects_peer_group_md5_inheritance() {
    let mut source = dynamic_tcp_ao_toml(
        r#"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#,
    );
    source = source.replace(
        "hold_time = 90",
        "hold_time = 90\nmd5_password = \"legacy\"",
    );
    let err = parse(&source).unwrap_err();
    assert!(err.to_string().contains("never inherited"));
}

#[test]
fn dynamic_neighbor_invalid_prefix_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90

[[dynamic_neighbors]]
prefix = "not-a-prefix"
peer_group = "ix-members"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("invalid prefix"));
}

#[test]
fn dynamic_neighbor_peer_group_with_bfd_rejected() {
    // v1 BFD is static-neighbors only (ADR-0067). A dynamic range whose peer
    // group enables BFD must be rejected so the operator isn't misled into
    // thinking dynamic peers are BFD-protected.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[bfd_profiles]]
name = "fast"

[peer_groups.ix-members]
hold_time = 90
bfd = { profile = "fast" }

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
"#;
    let err = parse(toml).unwrap_err();
    assert!(
        err.to_string()
            .contains("BFD is not supported for dynamic neighbors"),
        "unexpected error: {err}"
    );

    // The same group with BFD explicitly disabled is accepted.
    let ok = toml.replace(
        r#"bfd = { profile = "fast" }"#,
        r#"bfd = { profile = "fast", enabled = false }"#,
    );
    assert!(
        parse(&ok).is_ok(),
        "explicitly-disabled BFD should be allowed"
    );
}

#[test]
fn dynamic_neighbor_ipv4_prefix_too_long_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90

[[dynamic_neighbors]]
prefix = "10.0.0.0/40"
peer_group = "ix-members"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("IPv4 prefix length"));
}

#[test]
fn dynamic_neighbor_ipv6_prefix_too_long_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-v6]
hold_time = 90

[[dynamic_neighbors]]
prefix = "2001:db8::/129"
peer_group = "ix-v6"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("IPv6 prefix length"));
}

#[test]
fn dynamic_neighbor_missing_peer_group_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "nonexistent"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("not defined"));
}

#[test]
fn dynamic_neighbor_duplicate_effective_prefix_rejected() {
    // 10.0.0.0/24 and 10.0.0.9/24 both normalize to 10.0.0.0/24 — ambiguous.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.g]
families = ["ipv4_unicast"]

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "g"

[[dynamic_neighbors]]
prefix = "10.0.0.9/24"
peer_group = "g"
"#;
    let err = parse(toml).unwrap_err();
    assert!(
        err.to_string().contains("duplicate effective prefix"),
        "{err}"
    );
}

#[test]
fn dynamic_neighbor_overlapping_different_lengths_allowed() {
    // Overlapping ranges of DIFFERENT lengths are fine — longest-prefix-match
    // resolves them at accept time, so this must NOT be rejected.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.g]
families = ["ipv4_unicast"]

[[dynamic_neighbors]]
prefix = "10.0.0.0/16"
peer_group = "g"

[[dynamic_neighbors]]
prefix = "10.0.5.0/24"
peer_group = "g"
"#;
    parse(toml).expect("overlapping ranges of different lengths are allowed");
}

#[test]
fn static_neighbor_remote_asn_zero_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 0
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("remote_asn"));
}

#[test]
fn dynamic_neighbor_limit_zero_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
dynamic_neighbor_limit = 0
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("dynamic_neighbor_limit"));
}

#[test]
fn dynamic_neighbor_limit_valid_accepted() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
dynamic_neighbor_limit = 500
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(config.global.dynamic_neighbor_limit, Some(500));
}

#[test]
fn dynamic_neighbor_ipv6_prefix_parses() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-v6]
hold_time = 90

[[dynamic_neighbors]]
prefix = "2001:db8::/32"
peer_group = "ix-v6"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(config.dynamic_neighbors[0].prefix, "2001:db8::/32");
}

#[test]
fn dynamic_neighbors_diff_marks_reload_applied() {
    let old_toml = format!(
        r#"
{}

[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let new_toml = format!(
        r#"
{}

[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.3.0/24"
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let json = config_diff_json_value(&diff);
    let text = format_config_diff(&diff);

    assert!(diff.dynamic_neighbors_changed);
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    assert_eq!(
        json["reload_applied"]["dynamic_neighbors_changed"],
        serde_json::Value::Bool(true)
    );
    assert!(text.contains("[[dynamic_neighbors]] matcher rebuilt"));
}
