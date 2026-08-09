use super::*;

#[test]
fn bmp_valid_config_accepted() {
    let config = parse(&bmp_toml("")).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(bmp.sys_name, "rustbgpd");
    assert_eq!(bmp.collectors.len(), 1);
    assert_eq!(bmp.collectors[0].reconnect_interval, 30);
    assert_eq!(
        bmp.collectors[0].monitor,
        vec![BmpMonitorView::RibInPre],
        "default monitor selection is pre-RFC 8671 rib-in only"
    );
}

#[test]
fn bmp_monitor_rib_out_post_accepted() {
    let config = parse(&bmp_toml(r#"monitor = ["rib_in_pre", "rib_out_post"]"#)).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(
        bmp.collectors[0].monitor,
        vec![BmpMonitorView::RibInPre, BmpMonitorView::RibOutPost]
    );
}

#[test]
fn bmp_monitor_loc_rib_accepted() {
    let config = parse(&bmp_toml(r#"monitor = ["loc_rib"]"#)).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(
        bmp.collectors[0].monitor,
        vec![BmpMonitorView::LocRib],
        "RFC 9069 Loc-RIB view is selectable on its own"
    );
}

#[test]
fn bmp_empty_monitor_rejected() {
    let err = parse(&bmp_toml("monitor = []")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}

#[test]
fn bmp_unknown_monitor_value_rejected() {
    assert!(parse(&bmp_toml(r#"monitor = ["rib_out_pre"]"#)).is_err());
}

#[test]
fn bmp_invalid_collector_address_rejected() {
    let err = parse(&bmp_toml("").replace("127.0.0.1:11019", "not-a-socket-addr")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}

#[test]
fn bmp_zero_reconnect_interval_rejected() {
    let err = parse(&bmp_toml("reconnect_interval = 0")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}

#[test]
fn bmp_version_defaults_to_3() {
    let config = parse(&bmp_toml("")).unwrap();
    assert_eq!(
        config.bmp.as_ref().unwrap().collectors[0].version,
        3,
        "BMP wire version defaults to RFC 7854 v3"
    );
}

#[test]
fn bmp_version_4_accepted() {
    let config = parse(&bmp_toml("version = 4")).unwrap();
    assert_eq!(config.bmp.as_ref().unwrap().collectors[0].version, 4);
}

#[test]
fn bmp_invalid_version_rejected() {
    for bad in ["version = 2", "version = 5"] {
        let err = parse(&bmp_toml(bad)).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
    }
}

#[test]
fn bmp_custom_reconnect_interval_accepted() {
    let config = parse(&bmp_toml("reconnect_interval = 60")).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(bmp.collectors[0].reconnect_interval, 60);
}

#[test]
fn bmp_empty_collectors_accepted() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[bmp]
"#;
    let config = parse(toml).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert!(bmp.collectors.is_empty());
}

#[test]
fn bmp_custom_sys_name_accepted() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[bmp]
sys_name = "my-router"
sys_descr = "production edge"
[[bmp.collectors]]
address = "127.0.0.1:11019"
"#;
    let config = parse(toml).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(bmp.sys_name, "my-router");
    assert_eq!(bmp.sys_descr, "production edge");
}

#[test]
fn gnmi_dialout_valid_config_accepted_with_defaults() {
    let config = parse(&gnmi_dialout_toml("")).unwrap();
    let section = config.gnmi_dialout.as_ref().unwrap();
    assert_eq!(section.targets.len(), 1);
    let target = &section.targets[0];
    assert_eq!(target.name, "collector-a");
    assert_eq!(target.mode, GnmiDialoutModeConfig::Sample);
    assert_eq!(target.sample_interval, 10);
    assert_eq!(target.backoff_initial, 1);
    assert_eq!(target.backoff_max, 30);
    assert!(target.tls_ca_file.is_none());

    let targets = super::gnmi_dialout_targets(&config).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].endpoint, "http://192.0.2.10:57400",
        "no TLS section dials plaintext"
    );
}

#[test]
fn gnmi_dialout_tls_target_builds_https_endpoint() {
    let config = parse(&gnmi_dialout_toml(
        "tls_ca_file = \"/etc/rustbgpd/collector-ca.pem\"\n\
         tls_cert_file = \"/etc/rustbgpd/client.pem\"\n\
         tls_key_file = \"/etc/rustbgpd/client.key\"\n\
         tls_server_name = \"collector.example\"",
    ))
    .unwrap();
    let targets = super::gnmi_dialout_targets(&config).unwrap();
    assert_eq!(targets[0].endpoint, "https://192.0.2.10:57400");
    let tls = targets[0].tls.as_ref().unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("collector.example"));
}

#[test]
fn gnmi_dialout_duplicate_target_name_rejected() {
    let toml = gnmi_dialout_toml("")
        + "\n[[gnmi_dialout.targets]]\nname = \"collector-a\"\naddress = \"192.0.2.11:57400\"\npaths = [\"network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state/as\"]\n";
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_invalid_address_rejected() {
    for bad in ["no-port", ":57400", "192.0.2.10:notaport", ""] {
        let err = parse(&gnmi_dialout_toml("").replace("192.0.2.10:57400", bad)).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidGnmiDialout { .. }),
            "expected InvalidGnmiDialout for address {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn gnmi_dialout_empty_paths_rejected() {
    let toml = gnmi_dialout_toml("").replace(
        &format!("paths = [\"{DIALOUT_SESSION_STATE_PATH}\"]"),
        "paths = []",
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_unsupported_path_rejected() {
    // The same validation a dial-in Subscribe would apply: paths outside
    // the supported OpenConfig BGP surface fail at config load.
    let toml = gnmi_dialout_toml("").replace(
        DIALOUT_SESSION_STATE_PATH,
        "interfaces/interface[name=eth0]/state",
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_tls_pairing_rules_enforced() {
    // Cert without key.
    let err = parse(&gnmi_dialout_toml(
        "tls_ca_file = \"/etc/ca.pem\"\ntls_cert_file = \"/etc/client.pem\"",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
    // Cert+key without CA.
    let err = parse(&gnmi_dialout_toml(
        "tls_cert_file = \"/etc/client.pem\"\ntls_key_file = \"/etc/client.key\"",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
    // Server-name override without CA (no TLS at all).
    let err = parse(&gnmi_dialout_toml(
        "tls_server_name = \"collector.example\"",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_on_change_requires_event_history() {
    let err = parse(&gnmi_dialout_toml("mode = \"on_change\"")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));

    // With the durable outbox enabled, ON_CHANGE on the session-state
    // leaf is accepted.
    let toml = format!(
        "{}\n[event_history]\nenabled = true\n",
        gnmi_dialout_toml("mode = \"on_change\"")
    );
    parse(&toml).unwrap();
}

#[test]
fn gnmi_dialout_on_change_unsupported_leaf_rejected() {
    // ON_CHANGE is only supported on the session-state leaf, exactly like
    // dial-in Subscribe.
    let toml = format!(
        "{}\n[event_history]\nenabled = true\n",
        gnmi_dialout_toml("mode = \"on_change\"").replace(
            DIALOUT_SESSION_STATE_PATH,
            "network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state/as",
        )
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGnmiDialout { .. }));
}

#[test]
fn gnmi_dialout_timer_bounds_enforced() {
    for bad in [
        "sample_interval = 0",
        "backoff_initial = 0",
        "backoff_initial = 10\nbackoff_max = 5",
    ] {
        let err = parse(&gnmi_dialout_toml(bad)).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidGnmiDialout { .. }),
            "expected InvalidGnmiDialout for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn gnmi_dialout_unknown_field_rejected() {
    assert!(parse(&gnmi_dialout_toml("bogus_field = true")).is_err());
}

#[test]
fn gnmi_dialout_absent_section_yields_no_targets() {
    let toml = gnmi_dialout_toml("");
    let stripped = toml.split("[gnmi_dialout]").next().unwrap();
    let config = parse(stripped).unwrap();
    assert!(config.gnmi_dialout.is_none());
    assert!(super::gnmi_dialout_targets(&config).unwrap().is_empty());
}

#[test]
fn bmp_duplicate_collector_address_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[bmp]
[[bmp.collectors]]
address = "127.0.0.1:11019"
[[bmp.collectors]]
address = "127.0.0.1:11019"
"#;
    let err = parse(toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}
