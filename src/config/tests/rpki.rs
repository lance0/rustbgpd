use super::*;

// --- RPKI config tests ---

#[test]
fn rpki_single_cache_server_parses() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"
"#;
    let config = parse(toml_str).unwrap();
    let rpki = config.rpki.as_ref().unwrap();
    assert_eq!(rpki.cache_servers.len(), 1);
    assert_eq!(rpki.cache_servers[0].address, "127.0.0.1:3323");
    // Check defaults
    assert_eq!(rpki.cache_servers[0].refresh_interval, 3600);
    assert_eq!(rpki.cache_servers[0].retry_interval, 600);
    assert_eq!(rpki.cache_servers[0].expire_interval, 7200);
    assert_eq!(rpki.cache_servers[0].max_expire_interval, None);
}

#[test]
fn rpki_multiple_cache_servers_parses() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "10.0.0.10:3323"
refresh_interval = 1800
retry_interval = 300
expire_interval = 3600

[[rpki.cache_servers]]
address = "10.0.0.11:8282"
"#;
    let config = parse(toml_str).unwrap();
    let rpki = config.rpki.as_ref().unwrap();
    assert_eq!(rpki.cache_servers.len(), 2);
    assert_eq!(rpki.cache_servers[0].refresh_interval, 1800);
    assert_eq!(rpki.cache_servers[0].retry_interval, 300);
    assert_eq!(rpki.cache_servers[0].expire_interval, 3600);
    // Second server uses defaults
    assert_eq!(rpki.cache_servers[1].refresh_interval, 3600);
}

#[test]
fn rpki_absent_means_none() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.rpki.is_none());
}

#[test]
fn rpki_policy_match_rpki_validation_parses() {
    let toml = community_export_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(export.policies[0].entries.len(), 1);
    assert_eq!(
        export.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Invalid)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_valid() {
    let toml = community_export_toml(
        r#"action = "permit"
            match_rpki_validation = "valid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(
        export.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Valid)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_not_found() {
    let toml = community_export_toml(
        r#"action = "permit"
            match_rpki_validation = "not_found""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(
        export.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::NotFound)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_bad_value_rejected() {
    let toml = community_toml(
        r#"action = "deny"
            match_rpki_validation = "unknown_state""#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn rpki_policy_match_rpki_validation_standalone() {
    // match_rpki_validation alone (without prefix/community/aspath) is valid in export policy
    let toml = community_export_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    assert!(parse(&toml).is_ok());
}

#[test]
fn rpki_policy_match_rpki_validation_import_accepted() {
    let toml = community_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(
        import.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Invalid)
    );
}

#[test]
fn aspa_policy_match_aspa_validation_import_accepted() {
    let toml = community_toml(
        r#"action = "deny"
            match_aspa_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(
        import.policies[0].entries[0].match_aspa_validation,
        Some(rustbgpd_wire::AspaValidation::Invalid)
    );
}

#[test]
fn aspa_policy_match_aspa_validation_export_parses() {
    let toml = community_export_toml(
        r#"action = "deny"
            match_aspa_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(
        export.policies[0].entries[0].match_aspa_validation,
        Some(rustbgpd_wire::AspaValidation::Invalid)
    );
}

#[test]
fn rpki_cache_address_rejects_hostname_with_index_and_value() {
    let source = rpki_toml("").replace("127.0.0.1:3323", "rpki.example.com:3323");
    let err = parse(&source).unwrap_err().to_string();
    assert!(err.contains("cache_servers[0]"), "{err}");
    assert!(err.contains(r#""rpki.example.com:3323""#), "{err}");
}

#[test]
fn rpki_cache_address_rejects_canonical_duplicate() {
    let mut source = rpki_toml("").replace("127.0.0.1:3323", "[2001:0db8::1]:3323");
    source.push_str(
        r#"
[[rpki.cache_servers]]
address = "[2001:db8:0:0:0:0:0:1]:3323"
"#,
    );
    let err = parse(&source).unwrap_err().to_string();
    assert!(err.contains("cache_servers[1]"), "{err}");
    assert!(err.contains(r#""[2001:db8:0:0:0:0:0:1]:3323""#), "{err}");
}

#[test]
fn rpki_cache_address_accepts_unique_numeric_ipv4_and_ipv6() {
    let mut source = rpki_toml("");
    source.push_str(
        r#"
[[rpki.cache_servers]]
address = "[2001:db8::1]:3323"
"#,
    );
    assert!(parse(&source).is_ok());
}

#[test]
fn rpki_zero_refresh_interval_rejected() {
    let err = parse(&rpki_toml("refresh_interval = 0"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("cache_servers[0]: refresh_interval"), "{err}");
}

#[test]
fn rpki_zero_retry_interval_rejected() {
    let err = parse(&rpki_toml("retry_interval = 0"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("cache_servers[0]: retry_interval"), "{err}");
}

#[test]
fn rpki_zero_expire_interval_rejected() {
    let err = parse(&rpki_toml("expire_interval = 0"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("cache_servers[0]: expire_interval"), "{err}");
}

#[test]
fn rpki_expire_less_than_refresh_rejected() {
    let err = parse(&rpki_toml(
        "refresh_interval = 3600\nexpire_interval = 1800",
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("cache_servers[0]: expire_interval"), "{err}");
}

#[test]
fn rpki_expire_equals_refresh_accepted() {
    assert!(
        parse(&rpki_toml(
            "refresh_interval = 3600\nexpire_interval = 3600",
        ))
        .is_ok()
    );
}

#[test]
fn rpki_valid_custom_timers_accepted() {
    let config = parse(&rpki_toml(
        "refresh_interval = 1800\nretry_interval = 300\nexpire_interval = 3600",
    ))
    .unwrap();
    let rpki = config.rpki.as_ref().unwrap();
    assert_eq!(rpki.cache_servers[0].refresh_interval, 1800);
    assert_eq!(rpki.cache_servers[0].retry_interval, 300);
    assert_eq!(rpki.cache_servers[0].expire_interval, 3600);
}

#[test]
fn rpki_max_expire_interval_accepted_and_parsed() {
    let config = parse(&rpki_toml(
        "refresh_interval = 600\nmax_expire_interval = 1800",
    ))
    .unwrap();
    let rpki = config.rpki.as_ref().unwrap();
    assert_eq!(rpki.cache_servers[0].max_expire_interval, Some(1800));
}

#[test]
fn rpki_max_expire_interval_above_two_day_maximum_rejected() {
    let err = parse(&rpki_toml("max_expire_interval = 172801"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cache_servers[0]: max_expire_interval (172801) must be <= 172800"),
        "{err}"
    );
}

#[test]
fn rpki_max_expire_interval_not_above_refresh_rejected() {
    let err = parse(&rpki_toml("max_expire_interval = 3600"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(
            "cache_servers[0]: max_expire_interval (3600) must be > refresh_interval (3600)"
        ),
        "{err}"
    );
}

#[test]
fn rpki_max_expire_interval_not_above_retry_rejected() {
    let err = parse(&rpki_toml(
        "refresh_interval = 300\nmax_expire_interval = 600",
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("cache_servers[0]: max_expire_interval (600) must be > retry_interval (600)"),
        "{err}"
    );
}

#[test]
fn rpki_cache_server_md5_password_parses_and_never_debug_prints() {
    let config = parse(&rpki_toml("md5_password = \"rtr-md5-hunter2\"")).unwrap();
    let server = &config.rpki.as_ref().unwrap().cache_servers[0];
    assert_eq!(server.md5_password.as_deref(), Some("rtr-md5-hunter2"));
    assert!(server.tcp_ao.is_none());
    let debug = format!("{server:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

#[test]
fn rpki_cache_server_rejects_empty_and_oversized_md5_passwords() {
    for password in [String::new(), "k".repeat(81), "é".repeat(41)] {
        let err = parse(&rpki_toml(&format!("md5_password = {password:?}")))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cache_servers[0]: md5_password must be 1..=80 bytes"),
            "{err}"
        );
    }
}

#[test]
fn rpki_cache_server_tcp_ao_parses_in_neighbor_shape() {
    let config = parse(&rpki_toml(
        "tcp_ao = { key = \"rtr-ao-hunter2\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }",
    ))
    .unwrap();
    let server = &config.rpki.as_ref().unwrap().cache_servers[0];
    let ring = server.tcp_ao.as_ref().unwrap();
    assert_eq!(ring.len(), 1);
    assert_eq!((ring.0[0].send_id, ring.0[0].recv_id), (1, 2));
    let transport = transport_tcp_ao_keyring(ring);
    assert_eq!(transport.0.len(), 1);
    assert_eq!(transport.selected().unwrap().send_id, 1);
    assert!(!format!("{server:?}").contains("hunter2"));
}

#[test]
fn rpki_cache_server_rejects_md5_with_tcp_ao_and_invalid_tcp_ao() {
    let err = parse(&rpki_toml(
        "md5_password = \"x\"\ntcp_ao = { key = \"k\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }",
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("cache_servers[0]"), "{err}");
    assert!(err.contains("mutually exclusive"), "{err}");

    let err = parse(&rpki_toml(
        "tcp_ao = { key = \"k\", send_id = 1, recv_id = 2, algorithm = \"md5\" }",
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("cache_servers[0]"), "{err}");
    assert!(err.contains("tcp_ao.algorithm"), "{err}");

    let err = parse(&rpki_toml(
        "tcp_ao = { key = \"\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }",
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("tcp_ao.key"), "{err}");
}

#[test]
fn rpki_cache_server_secrets_are_redacted_in_effective_dump() {
    for fields in [
        "md5_password = \"rtr-md5-hunter2\"",
        "tcp_ao = { key = \"rtr-ao-hunter2\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }",
    ] {
        let mut config = parse(&rpki_toml(fields)).unwrap();
        let rendered = config.effective_redacted_toml().unwrap();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains(REDACTED_SECRET), "{rendered}");
        let err = Config::load_toml_with_diagnostics(&rendered, "effective.toml").unwrap_err();
        assert!(err.contains("rbgp config effective"), "{err}");
        assert!(
            err.contains("invalid RPKI config: cache_servers[0]"),
            "{err}"
        );
    }
}
