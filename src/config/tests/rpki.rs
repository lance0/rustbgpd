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
