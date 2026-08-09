use super::*;

#[test]
fn grpc_listeners_default_to_uds() {
    let config = parse_schema_only(valid_toml()).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Uds {
            path: PathBuf::from("/var/lib/rustbgpd/grpc.sock"),
            mode: 0o600,
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::OperatorOnly,
            token_file: None,
            principal: None,
        }]
    );
}

#[test]
fn grpc_tcp_listener_parses_when_enabled() {
    // An explicit TCP listener no longer suppresses the implicit local
    // UDS listener; it rides alongside.
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\n",
        valid_toml()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![
            GrpcListener::Tcp {
                addr: "127.0.0.1:50051".parse().unwrap(),
                access_mode: GrpcAccessMode::ReadWrite,
                max_tier: GrpcMaxTier::OperatorOnly,
                token_file: None,
                principal: None,
                tls: None,
            },
            implicit_uds_listener(&config),
        ]
    );
}

#[test]
fn grpc_explicit_uds_opt_out_disables_the_implicit_listener() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\n\n[global.telemetry.grpc_uds]\nenabled = false\n",
        valid_toml()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    let listeners = config.grpc_listeners();
    assert_eq!(listeners.len(), 1);
    assert!(matches!(listeners[0], GrpcListener::Tcp { .. }));
}

#[test]
fn grpc_listener_access_mode_parses() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\naccess_mode = \"read_only\"\n",
        valid_toml()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![
            GrpcListener::Tcp {
                addr: "127.0.0.1:50051".parse().unwrap(),
                access_mode: GrpcAccessMode::ReadOnly,
                max_tier: GrpcMaxTier::SensitiveRead,
                token_file: None,
                principal: None,
                tls: None,
            },
            implicit_uds_listener(&config),
        ]
    );
}

#[test]
fn grpc_listener_max_tier_parses() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\nmax_tier = \"mutating\"\n",
        valid_toml()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![
            GrpcListener::Tcp {
                addr: "127.0.0.1:50051".parse().unwrap(),
                access_mode: GrpcAccessMode::ReadWrite,
                max_tier: GrpcMaxTier::Mutating,
                token_file: None,
                principal: None,
                tls: None,
            },
            implicit_uds_listener(&config),
        ]
    );
}

#[test]
fn grpc_listener_access_mode_read_only_caps_max_tier() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\naccess_mode = \"read_only\"\nmax_tier = \"operator_only\"\n",
        valid_toml()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![
            GrpcListener::Tcp {
                addr: "127.0.0.1:50051".parse().unwrap(),
                access_mode: GrpcAccessMode::ReadOnly,
                max_tier: GrpcMaxTier::SensitiveRead,
                token_file: None,
                principal: None,
                tls: None,
            },
            implicit_uds_listener(&config),
        ]
    );
}

#[test]
fn grpc_listener_max_tier_can_be_stricter_than_access_mode() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nmax_tier = \"read\"\n",
        valid_toml()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Uds {
            path: PathBuf::from("/tmp/rustbgpd-test.sock"),
            mode: 0o600,
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::Read,
            token_file: None,
            principal: None,
        }]
    );
}

#[test]
fn explicit_legacy_grpc_enforcement_is_rejected() {
    // Load-bearing: restoring the enum variant bypasses the post-deserialize
    // migration detector and makes this config load; removing the exact-path
    // detector replaces the paste-ready guidance with a generic enum error.
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"legacy\"\n\n[security.grpc.roles]\n\"operator.example\" = \"operator\"\n",
        valid_toml_no_grpc_security()
    );
    let err = Config::load_toml_with_diagnostics(&toml_str, "legacy removal")
        .expect_err("legacy enforcement must fail validation");
    assert!(
        err.starts_with("error: security.grpc.enforcement"),
        "migration guidance must retain the standard diagnostic heading: {err}"
    );
    assert!(
        err.contains("security.grpc.enforcement = \"legacy\" was removed in v0.63.0"),
        "rejection must name the removal decision: {err}"
    );
    // Local-only operators get the zero-config exit: the implicit
    // local-operator identity covers owner-only UDS clients.
    assert!(
        err.contains("delete the whole [security.grpc] block") && err.contains("local-operator"),
        "rejection must give the delete-the-block guidance: {err}"
    );
    // Named-principal setups get the paste block for the tier config to keep.
    assert!(
        err.contains("[security.grpc]\nenforcement = \"tier\"")
            && err.contains("[security.grpc.roles]\n\"<your-principal>\" = \"operator\""),
        "rejection must carry the copy-pasteable tier fix: {err}"
    );
    assert!(
        err.contains("docs/CONFIGURATION.md") && err.contains("docs/adr/0064"),
        "rejection must cite the migration references: {err}"
    );
}

#[test]
fn legacy_grpc_migration_detection_is_semantic_and_fail_closed() {
    let base = valid_toml_no_grpc_security();
    Config::load_toml_with_diagnostics(
        &format!("{base}\n# [security.grpc]\n# enforcement = \"legacy\"\n"),
        "legacy comment control",
    )
    .expect("a comment must not trigger retired-value detection");

    for (name, suffix, ordinary_needle) in [
        (
            "unrelated table",
            "[unrelated]\nenforcement = \"legacy\"\n",
            "unknown field `unrelated`",
        ),
        (
            "unrelated string",
            "migration_note = 'security.grpc.enforcement = \"legacy\"'\n",
            "unknown field `migration_note`",
        ),
        (
            "bogus enum",
            "[security.grpc]\nenforcement = \"bogus\"\n",
            "unknown variant `bogus`",
        ),
        (
            "malformed toml",
            "[security.grpc\nenforcement = \"legacy\"\n",
            "unclosed table",
        ),
    ] {
        let error = Config::load_toml_with_diagnostics(&format!("{base}\n{suffix}"), name)
            .expect_err("invalid control must retain its ordinary diagnostic");
        assert!(error.contains(ordinary_needle), "{name}: {error}");
        assert!(
            !error.contains("was removed in v0.63.0"),
            "{name} falsely triggered the legacy migration pointer: {error}"
        );
    }
}

#[test]
fn grpc_security_default_is_tier_since_v0_24() {
    // Pinned by the v0.24.0 ADR-0064 slice 4b default flip. If this
    // regresses to Legacy without a deliberate schema change, the
    // production security posture has silently rolled back. The
    // owner-only UDS listener needs no principal or roles: the
    // implicit `local-operator` identity authorizes it under tier.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-default-tier-test.sock"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90
"#;
    // Strict parsing observes the production schema default without adding
    // the test helper's canonical Tier identity.
    let config = parse_strict(toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier,
        "GrpcEnforcementConfig default flipped to Tier in v0.24.0; \
         regression would silently restore pre-enforcement behavior"
    );
}

#[test]
fn grpc_security_zero_config_boots_under_tier_with_implicit_local_operator() {
    // Red proof for the implicit local-operator rule: a config with no
    // [security.grpc] block and no declared listener is valid under the
    // default tier enforcement — the implicit owner-only UDS listener
    // authorizes the socket owner as `local-operator`. Removing the
    // implicit rule (or the implicit listener) fails this test.
    let toml_str = r#"
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
"#;
    let config = parse_strict(toml_str).expect("zero-config boot must validate under tier");
    assert_eq!(
        config.grpc_listeners(),
        vec![implicit_uds_listener(&config)]
    );
}

#[test]
fn grpc_security_tier_enforcement_parses_with_explicit_uds_principal() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"local-admin\" = \"operator\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml_no_grpc_security()
    );
    let config = parse_strict(&toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier
    );
    assert_eq!(
        config.security.grpc.roles["local-admin"],
        GrpcRoleConfig::Operator
    );
}

#[test]
fn grpc_security_empty_role_principal_rejected() {
    let toml_str = format!(
        "{}\n[security.grpc.roles]\n\"   \" = \"observer\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("principal keys must not be empty"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_reserved_unresolved_mtls_role_rejected() {
    let toml_str = format!(
        "{}\n[security.grpc.roles]\n\"mtls-unresolved\" = \"operator\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("reserved principal"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_diagnoses_uds_principal_missing_from_roles() {
    // WP1 one-shot diagnosis: a declared UDS principal with no roles
    // entry gets one error ending in a paste-ready fix built from the
    // operator's own principal string. Red proof: dropping the paste
    // block from the message fails this test.
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml_no_grpc_security()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("grpc_uds.principal \"local-admin\" has no"),
        "got unexpected reason: {reason}"
    );
    assert!(
        reason.contains("add this to fix it:")
            && reason.contains("[security.grpc.roles]")
            && reason.contains("\"local-admin\" = \"operator\""),
        "error must end with a paste-ready fix: {reason}"
    );
    // v0.63.0 removed the legacy escape hatch; the fix must not
    // resurrect it.
    assert!(
        !reason.contains("enforcement = \"legacy\""),
        "error must not offer the removed legacy mode: {reason}"
    );
    assert!(
        reason.contains("docs/CONFIGURATION.md"),
        "error must point at the migration checklist: {reason}"
    );
}

#[test]
fn grpc_security_tier_accepts_implicit_uds_via_local_operator() {
    // Tier enforcement with roles staged but no declared listener:
    // the implicit owner-only UDS authorizes as `local-operator`.
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"local-admin\" = \"operator\"\n",
        valid_toml_no_grpc_security()
    );
    parse_strict(&toml_str).expect("implicit UDS must validate under tier");
}

#[test]
fn grpc_security_tier_accepts_owner_only_uds_without_principal() {
    // A declared UDS listener with the default owner-only mode and no
    // principal relies on the implicit `local-operator` identity.
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\n",
        valid_toml_no_grpc_security()
    );
    parse_strict(&toml_str).expect("owner-only UDS without principal must validate under tier");
}

#[test]
fn grpc_security_tier_rejects_group_accessible_uds_without_principal() {
    // Red proof for the owner-only gate: widening the implicit rule to
    // accept group-accessible modes (e.g. 0o660) makes this config
    // valid and fails this test. Group/world access buys real scoping,
    // so it keeps the explicit principal ceremony.
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nmode = 0o660\n",
        valid_toml_no_grpc_security()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("group/world-accessible (mode 0o660)") && reason.contains("local-operator"),
        "got unexpected reason: {reason}"
    );
    assert!(
        reason.contains("add this to fix it:")
            && reason.contains("principal = \"local-admin\"")
            && reason.contains("\"local-admin\" = \"operator\""),
        "error must end with a paste-ready fix: {reason}"
    );
}

#[test]
fn grpc_security_tier_diagnoses_bearer_tcp_without_principal() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"automation.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\n",
        valid_toml_no_grpc_security(),
        token_file.path()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("bearer-token TCP listener has no grpc_tcp.principal"),
        "got unexpected reason: {reason}"
    );
    assert!(
        reason.contains("add this to fix it:")
            && reason.contains("[global.telemetry.grpc_tcp]")
            && reason.contains("principal = \"automation\""),
        "error must end with a paste-ready fix: {reason}"
    );
}

#[test]
fn grpc_security_tier_diagnoses_non_mtls_principal_absent_from_roles() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"other.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\nprincipal = \"automation.example\"\n",
        valid_toml_no_grpc_security(),
        token_file.path()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("grpc_tcp.principal \"automation.example\" has no"),
        "got unexpected reason: {reason}"
    );
    assert!(
        reason.contains("add this to fix it:")
            && reason.contains("\"automation.example\" = \"operator\""),
        "error must interpolate the operator's own principal into the fix: {reason}"
    );
}

#[test]
fn grpc_security_tier_diagnoses_unauthenticated_tcp() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"automation.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\n",
        valid_toml_no_grpc_security()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("TCP listener is unauthenticated"),
        "got unexpected reason: {reason}"
    );
    assert!(
        reason.contains("add this to fix it:") && reason.contains("token_file = "),
        "error must end with a paste-ready fix: {reason}"
    );
}

#[test]
fn grpc_security_tier_reports_all_problems_in_one_error() {
    // The whole point of the one-shot diagnosis: two independent
    // problems surface in one numbered error, not one per boot attempt.
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nmode = 0o660\n",
        valid_toml_no_grpc_security()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("2 problem(s)") && reason.contains("  1. ") && reason.contains("  2. "),
        "both problems must appear in one error: {reason}"
    );
}

#[test]
fn grpc_security_reserved_local_operator_role_rejected() {
    // Red proof: dropping the reserved-name rejection lets an operator
    // map "local-operator" in roles and fails this test.
    let toml_str = format!(
        "{}\n[security.grpc.roles]\n\"local-operator\" = \"observer\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("reserved principal") && reason.contains("local-operator"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_listener_reserved_local_operator_principal_rejected() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-operator\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("reserved principal") && reason.contains("grpc_uds.principal"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_accepts_native_mtls_without_configured_principal() {
    let cert = write_pem(STUB_CERT);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"rustbgpd://operator/alice\" = \"operator\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml_no_grpc_security(),
        cert.path(),
        key.path(),
        ca.path()
    );
    let config = parse_strict(&toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier
    );
    let listeners = config.grpc_listeners();
    let GrpcListener::Tcp { principal, tls, .. } = &listeners[0] else {
        panic!("expected TCP listener");
    };
    assert_eq!(principal, &None);
    assert!(tls.is_some());
}

#[test]
fn grpc_tcp_principal_requires_bearer_token_without_mtls() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\nprincipal = \"automation.example\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("requires grpc_tcp.token_file"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_tcp_bearer_principal_parses() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\nprincipal = \"automation.example\"\n",
        valid_toml(),
        token_file.path()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![
            GrpcListener::Tcp {
                addr: "127.0.0.1:50051".parse().unwrap(),
                access_mode: GrpcAccessMode::ReadWrite,
                max_tier: GrpcMaxTier::OperatorOnly,
                token_file: Some(token_file.path().to_path_buf()),
                principal: Some("automation.example".to_string()),
                tls: None,
            },
            implicit_uds_listener(&config),
        ]
    );
}

#[test]
fn grpc_security_tier_accepts_bearer_tcp_with_principal_role() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"automation.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\nprincipal = \"automation.example\"\nmax_tier = \"mutating\"\n",
        valid_toml_no_grpc_security(),
        token_file.path()
    );
    let config = parse_strict(&toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier
    );
    assert_eq!(
        config.security.grpc.roles["automation.example"],
        GrpcRoleConfig::Automation
    );
    assert_eq!(
        config.grpc_listeners(),
        vec![
            GrpcListener::Tcp {
                addr: "127.0.0.1:50051".parse().unwrap(),
                access_mode: GrpcAccessMode::ReadWrite,
                max_tier: GrpcMaxTier::Mutating,
                token_file: Some(token_file.path().to_path_buf()),
                principal: Some("automation.example".to_string()),
                tls: None,
            },
            implicit_uds_listener(&config),
        ]
    );
}

#[test]
fn grpc_tcp_principal_rejected_with_mtls() {
    let cert = write_pem(STUB_CERT);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\nprincipal = \"automation.example\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("non-mTLS bearer-token listeners"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_uds_principal_parses() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml()
    );
    let config = parse_schema_only(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Uds {
            path: PathBuf::from("/tmp/rustbgpd-test.sock"),
            mode: 0o600,
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::OperatorOnly,
            token_file: None,
            principal: Some("local-admin".to_string()),
        }]
    );
}

#[test]
fn grpc_uds_relative_path_rejected() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"grpc.sock\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));
}

#[test]
fn grpc_tls_partial_config_rejected() {
    // Only cert_file set — must reject because mTLS requires all three.
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = \"/tmp/cert.pem\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));

    // cert + key but no client CA — still partial.
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = \"/tmp/cert.pem\"\ntls_key_file = \"/tmp/key.pem\"\n",
        valid_toml()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));
}

#[test]
fn grpc_tls_full_config_accepted() {
    // All three TLS files set together with real PEM content — should
    // parse cleanly. Validation now reads the files at config load /
    // `--check` time, so paths must point at readable PEM-shaped data.
    let cert = write_pem(STUB_CERT);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[security.grpc.roles]\n\"rustbgpd://operator/test-only\" = \"operator\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let config = parse_strict(&toml_str).unwrap();
    let listeners = config.grpc_listeners();
    assert_eq!(listeners.len(), 2, "TCP plus the implicit UDS listener");
    let GrpcListener::Tcp { tls, .. } = &listeners[0] else {
        panic!("expected Tcp listener");
    };
    assert!(
        tls.is_some(),
        "tls config must be populated when all three files are set"
    );
}

/// Pre-flight catches a missing cert path before the daemon starts.
/// Otherwise a successful `--check` could be followed by a startup
/// failure during cert rotation — the surprise the adversarial review
/// flagged.
#[test]
fn grpc_tls_missing_file_rejected_at_load() {
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = \"/tmp/rustbgpd-tls-does-not-exist.pem\"\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        key.path(),
        ca.path(),
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig, got {err:?}");
    };
    assert!(
        reason.contains("tls_cert_file") && reason.contains("failed to read"),
        "error must mention the offending field and read failure: {reason}"
    );
}

#[test]
fn grpc_tls_empty_file_rejected_at_load() {
    let cert = NamedTempFile::new().unwrap(); // empty
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(reason.contains("is empty"), "got: {reason}");
}

#[test]
fn grpc_tls_non_pem_file_rejected_at_load() {
    let cert = write_pem("not a pem file at all\n");
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("no PEM blocks"),
        "error must mention missing PEM markers: {reason}"
    );
}

/// Operator swapped the cert and key paths — file is structurally
/// PEM but the wrong kind. Catching this at load time prevents a
/// successful `--check` followed by a runtime TLS failure.
#[test]
fn grpc_tls_wrong_kind_pem_rejected_at_load() {
    // cert path points at a private key blob — wrong kind.
    let cert = write_pem(STUB_KEY);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let err = parse_strict(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("expected kind") && reason.contains("CERTIFICATE"),
        "error must mention the expected PEM kind: {reason}"
    );
}

#[test]
fn grpc_token_file_must_be_non_empty() {
    let token_file = NamedTempFile::new().unwrap();
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\n",
        valid_toml(),
        token_file.path()
    );
    let err = parse_strict(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));
}

// ── Tier gRPC enforcement (legacy mode removed in v0.63.0) ───────────

#[test]
fn tier_grpc_enforcement_does_not_warn() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"local-admin\" = \"operator\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml_no_grpc_security()
    );
    let config = parse_strict(&toml_str).unwrap();
    assert!(
        config.advisories().is_empty(),
        "no advisory expected: {:?}",
        config.advisories()
    );
}

#[test]
fn production_text_loader_preserves_default_tier_validation() {
    let error = Config::load_toml_with_diagnostics(&raw_tier_invalid_toml(), "raw-text.toml")
        .expect_err("raw text with an unmapped principal must fail closed");
    assert_raw_default_tier_rejected(&error);
}

#[test]
fn production_file_dataset_loader_preserves_default_tier_validation() {
    let file = raw_default_tier_config_file();
    let error = Config::load_with_diagnostics_and_datasets(file.path().to_str().unwrap(), None)
        .expect_err("raw file without gRPC authorization must fail closed");
    assert_raw_default_tier_rejected(&error);
}

#[test]
fn staged_dataset_loader_preserves_default_tier_validation() {
    let file = raw_default_tier_config_file();
    let error = Config::load_with_diagnostics_and_staged_datasets(
        file.path().to_str().unwrap(),
        &rustbgpd_policy::datasets::DatasetBindings::new(),
    )
    .expect_err("raw staged file without gRPC authorization must fail closed");
    assert_raw_default_tier_rejected(&error);
}

#[test]
fn config_loader_has_no_test_only_legacy_bypass() {
    let source = include_str!("../mod.rs");
    let (_, parse_source) = include_str!("mod.rs")
        .split_once("fn parse(toml_str")
        .unwrap();
    let (parse_source, _) = parse_source.split_once("#[test]").unwrap();
    assert!(
        parse_source.contains("tier_authorized_uds_test_config")
            && !parse_source.contains("legacy")
    );
    assert!(
        !source.contains("test_only_inject_legacy_grpc_security"),
        "production loader source must not contain a test-only auth seam"
    );
    assert_eq!(
        include_str!("../schema.rs").matches("Legacy,").count(),
        0,
        "the typed config schema must not accept Legacy"
    );
    assert_eq!(
        include_str!("../validation.rs")
            .matches("GrpcEnforcementConfig::Legacy")
            .count(),
        0,
        "validation must not retain a dead typed Legacy branch"
    );
    assert!(
        source.contains("LEGACY_GRPC_ENFORCEMENT_MIGRATION")
            && source.contains("let document: toml::Value = toml::from_str(content).ok()?")
            && source.contains(".get(\"security\")?")
            && source.contains(".get(\"grpc\")?")
            && source.contains(".get(\"enforcement\")?"),
        "the production loader must keep the exact semantic migration detector"
    );
}
