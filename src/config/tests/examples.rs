use super::*;

#[test]
fn config_examples_parse() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut examples = Vec::new();
    let mut explicit_uds_examples = Vec::new();
    let mut authenticated_tcp_examples = Vec::new();
    collect_example_toml_files(&root.join("examples"), &mut examples);
    examples.sort();

    assert!(
        examples
            .iter()
            .any(|path| path.ends_with("linux-edge-fib/config.toml")),
        "new Linux edge FIB example must be covered"
    );

    for path in examples {
        let label = path.strip_prefix(root).unwrap_or(&path).display();
        let source = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("failed to read example config {label}: {err}");
        });
        // The Docker Compose quick-start mounts the repository's public,
        // test-only bearer fixture at a container-absolute path. Substitute
        // the same fixture's host path so this production-path validation
        // proves the shipped config without weakening token-file checks.
        let source = materialize_shared_test_only_grpc_token(&source);
        // Strict parse keeps the shipped auth config intact, so every example
        // is validated under the production Tier default. An omitted listener
        // intentionally exercises the implicit owner-only UDS path; explicit
        // listeners must carry their own valid authorization boundary.
        // Referenced .rpol files compile against the example's directory,
        // exactly like the production load path, so chains resolve against
        // the combined TOML + rpol namespace (e.g. route-server's
        // hygiene.rpol).
        let mut config: Config = toml::from_str(&source).unwrap_or_else(|err| {
            panic!("example config {label} failed to parse: {err}");
        });
        config.load_rpol_files(path.parent()).unwrap_or_else(|err| {
            panic!("example config {label} failed to load rpol files: {err}");
        });
        config.validate().unwrap_or_else(|err| {
            panic!("example config {label} failed validation under the tier default: {err}");
        });

        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        if let Some(uds) = config.global.telemetry.grpc_uds.as_ref() {
            if relative == Path::new("examples/route-collector/config.toml") {
                assert_eq!(
                    uds.principal.as_deref(),
                    Some("looking-glass"),
                    "{label} must preserve the route-collector observer principal"
                );
                assert_eq!(
                    config.security.grpc.roles.get("looking-glass"),
                    Some(&GrpcRoleConfig::Observer),
                    "{label} must preserve the route-collector observer ceiling"
                );
            }
            explicit_uds_examples.push(relative.clone());
        }
        if let Some(tcp) = config
            .global
            .telemetry
            .grpc_tcp
            .as_ref()
            .filter(|tcp| tcp.enabled)
        {
            assert!(
                tcp.token_file.is_some() || tcp.tls_cert_file.is_some(),
                "example config {label} must authenticate its explicit TCP listener"
            );
            assert_eq!(
                tcp.principal.as_deref(),
                Some(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
                "{label} must preserve the Docker test-only principal"
            );
            assert_eq!(
                config
                    .security
                    .grpc
                    .roles
                    .get(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
                Some(&GrpcRoleConfig::Operator),
                "{label} must preserve the Docker operator ceiling"
            );
            authenticated_tcp_examples.push(relative);
        }
    }

    // Load-bearing ADR-0122 E1 inventory. Reintroducing explicit UDS ceremony
    // to an ordinary example, removing the collector's observer boundary, or
    // weakening/removing the Compose TCP boundary makes these exact rosters red.
    assert_eq!(
        explicit_uds_examples,
        [PathBuf::from("examples/route-collector/config.toml")]
    );
    assert_eq!(
        authenticated_tcp_examples,
        [PathBuf::from("examples/docker-compose/rustbgpd.toml")]
    );
}

#[test]
fn shared_test_only_operator_auth_is_tier_valid_and_wired() {
    // Load-bearing foundation for incrementally moving ordinary interop
    // configs off legacy authorization. Both migrated configs must use the
    // same public test-only credential path and stable operator principal;
    // their harnesses must mount that exact credential and opt into the
    // shared grpcurl helper.
    for (label, source) in [
        (
            "M1 ordinary interop",
            include_str!("../../../tests/interop/configs/rustbgpd-m1-frr.toml"),
        ),
        (
            "Docker Compose quick-start",
            include_str!("../../../examples/docker-compose/rustbgpd.toml"),
        ),
    ] {
        assert!(
            source.contains(TEST_ONLY_GRPC_TOKEN_CONTAINER_PATH),
            "{label} must use the shared test-only token path"
        );
        let materialized = materialize_shared_test_only_grpc_token(source);
        let config = parse_strict(&materialized)
            .unwrap_or_else(|err| panic!("{label} must validate under tier enforcement: {err}"));

        assert_eq!(
            config.security.grpc.enforcement,
            GrpcEnforcementConfig::Tier,
            "{label} must not fall back to legacy authorization"
        );
        let tcp = config
            .global
            .telemetry
            .grpc_tcp
            .as_ref()
            .unwrap_or_else(|| panic!("{label} must configure gRPC TCP"));
        assert!(tcp.enabled, "{label} gRPC TCP listener must be enabled");
        assert_eq!(
            tcp.principal.as_deref(),
            Some(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
            "{label} must preserve the stable test-only operator principal"
        );
        assert_eq!(
            config
                .security
                .grpc
                .roles
                .get(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
            Some(&GrpcRoleConfig::Operator),
            "{label} principal must map to the operator role"
        );
    }

    let m1_topology: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../tests/interop/m1-frr.clab.yml"))
            .expect("M1 topology must be YAML");
    let m1_binds = m1_topology["topology"]["nodes"]["rustbgpd"]["binds"]
        .as_sequence()
        .expect("M1 rustbgpd binds must be a sequence");
    assert!(
        m1_binds.iter().any(|bind| {
            bind.as_str()
                == Some(
                    "../fixtures/grpc-test-only-operator.token:/run/rustbgpd/grpc-test-only-operator.token:ro",
                )
        }),
        "M1 must mount the shared test-only token at its configured path"
    );

    let compose: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../examples/docker-compose/docker-compose.yml"
    ))
    .expect("Docker Compose quick-start must be YAML");
    let compose_service = &compose["services"]["rustbgpd"];
    let compose_volumes = compose_service["volumes"]
        .as_sequence()
        .expect("Compose rustbgpd volumes must be a sequence");
    assert!(
        compose_volumes.iter().any(|volume| {
            volume.as_str()
                == Some(
                    "../../tests/fixtures/grpc-test-only-operator.token:/run/rustbgpd/grpc-test-only-operator.token:ro",
                )
        }),
        "Compose must mount the shared test-only token at its configured path"
    );
    assert_eq!(
        compose_service["environment"]["RUSTBGPD_TOKEN_FILE"].as_str(),
        Some(TEST_ONLY_GRPC_TOKEN_CONTAINER_PATH),
        "Compose must inject the shared token path into in-container rbgp"
    );

    let m1_driver = include_str!("../../../tests/interop/scripts/test-m1-frr.sh");
    assert!(
        m1_driver.contains("INTEROP_TEST_OPERATOR_AUTH=1"),
        "M1 must opt into shared test-only grpcurl authentication"
    );
    assert!(
        m1_driver.matches("grpcurl_call").count() >= 2,
        "M1 route queries must use the shared grpcurl helper"
    );
    assert!(
        !m1_driver.contains("grpcurl -plaintext"),
        "M1 must not copy bearer-token plumbing around the shared helper"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one frozen inventory keeps config, topology, and driver wiring atomic"
)]
fn early_interop_auth_inventory_is_tier_wired() {
    // Load-bearing: reverting a config to legacy, dropping a token bind,
    // downgrading the operator role, bypassing the helper, removing a driver
    // opt-in, or removing an M0 UDS identity makes an assertion below red.
    const TCP_SLICES: &[(&str, &str)] = &[
        ("m3-frr.clab.yml", "test-m3-frr.sh"),
        ("m4-frr.clab.yml", "test-m4-frr.sh"),
        ("m10-frr-ipv6.clab.yml", "test-m10-frr-ipv6.sh"),
        ("m11-gr-frr.clab.yml", "test-m11-gr-frr.sh"),
        ("m12-ec-frr.clab.yml", "test-m12-ec-frr.sh"),
        ("m13-policy-frr.clab.yml", "test-m13-policy-frr.sh"),
        ("m14-rr-frr.clab.yml", "test-m14-rr-frr.sh"),
        ("m15-rr-frr.clab.yml", "test-m15-rr-frr.sh"),
        ("m16-llgr-frr.clab.yml", "test-m16-llgr-frr.sh"),
        ("m17-addpath-frr.clab.yml", "test-m17-addpath-frr.sh"),
        ("m18-extnexthop-frr.clab.yml", "test-m18-extnexthop-frr.sh"),
        (
            "m19-routeserver-frr.clab.yml",
            "test-m19-routeserver-frr.sh",
        ),
        ("m20-privateas-frr.clab.yml", "test-m20-privateas-frr.sh"),
        ("m21-rpki-frr.clab.yml", "test-m21-rpki-frr.sh"),
        ("m22-flowspec-frr.clab.yml", "test-m22-flowspec-frr.sh"),
        ("m23-gobgp.clab.yml", "test-m23-gobgp.sh"),
        ("m24-bmp-frr.clab.yml", "test-m24-bmp-frr.sh"),
        ("m25-md5-gtsm-frr.clab.yml", "test-m25-md5-gtsm-frr.sh"),
        ("m26-cease-frr.clab.yml", "test-m26-cease-frr.sh"),
        ("m27-aspa-rtr2.clab.yml", "test-m27-aspa-rtr2.sh"),
        ("m28-dynamic-frr.clab.yml", "test-m28-dynamic-frr.sh"),
        ("m29-evpn-rr-frr.clab.yml", "test-m29-evpn-rr-frr.sh"),
        ("m30-evpn-type2-frr.clab.yml", "test-m30-evpn-type2-frr.sh"),
        (
            "m30b-evpn-type5-frr.clab.yml",
            "test-m30b-evpn-type5-frr.sh",
        ),
        (
            "m31-evpn-mac-mobility-frr.clab.yml",
            "test-m31-evpn-mac-mobility-frr.sh",
        ),
        (
            "m32-evpn-multihome-frr.clab.yml",
            "test-m32-evpn-multihome-frr.sh",
        ),
        (
            "m32b-evpn-ead-synthetic.clab.yml",
            "test-m32b-evpn-ead-synthetic.sh",
        ),
        (
            "m34-policy-soft-reset-frr.clab.yml",
            "test-m34-policy-soft-reset-frr.sh",
        ),
        (
            "m35-graceful-shutdown-frr.clab.yml",
            "test-m35-graceful-shutdown-frr.sh",
        ),
        (
            "m35b-graceful-shutdown-flowspec-frr.clab.yml",
            "test-m35b-graceful-shutdown-flowspec-frr.sh",
        ),
        (
            "m35c-graceful-shutdown-evpn-frr.clab.yml",
            "test-m35c-graceful-shutdown-evpn-frr.sh",
        ),
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let interop = root.join("tests/interop");
    let expected_bind = format!(
        "../fixtures/grpc-test-only-operator.token:{TEST_ONLY_GRPC_TOKEN_CONTAINER_PATH}:ro"
    );
    let expected_token_path = root.join(TEST_ONLY_GRPC_TOKEN_REPO_PATH);
    let mut config_count = 0;

    for (topology_name, driver_name) in TCP_SLICES {
        let topology_source = fs::read_to_string(interop.join(topology_name))
            .unwrap_or_else(|err| panic!("failed to read {topology_name}: {err}"));
        let topology: serde_yaml::Value = serde_yaml::from_str(&topology_source)
            .unwrap_or_else(|err| panic!("failed to parse {topology_name}: {err}"));
        let binds = topology["topology"]["nodes"]["rustbgpd"]["binds"]
            .as_sequence()
            .unwrap_or_else(|| panic!("{topology_name} rustbgpd binds must be a sequence"));
        assert!(
            binds
                .iter()
                .any(|bind| bind.as_str() == Some(expected_bind.as_str())),
            "{topology_name} must mount the shared test-only token"
        );

        for bind in binds.iter().filter_map(serde_yaml::Value::as_str) {
            let Some((host_path, _)) = bind.split_once(':') else {
                continue;
            };
            if !host_path.starts_with("./configs/rustbgpd-")
                || !Path::new(host_path)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            {
                continue;
            }
            config_count += 1;
            let config_source =
                fs::read_to_string(interop.join(host_path.trim_start_matches("./")))
                    .unwrap_or_else(|err| panic!("failed to read {host_path}: {err}"));
            assert!(
                config_source.contains(TEST_ONLY_GRPC_TOKEN_CONTAINER_PATH),
                "{host_path} must use the shared test-only token path"
            );
            let materialized = materialize_shared_test_only_grpc_token(&config_source)
                .replace("BMP_RECEIVER_ADDR", "127.0.0.1")
                .replace("STAYRTR_ADDR", "127.0.0.1");
            let config = parse_strict(&materialized).unwrap_or_else(|err| {
                panic!("{host_path} must validate under tier enforcement: {err}")
            });
            assert_eq!(
                config.security.grpc.enforcement,
                GrpcEnforcementConfig::Tier,
                "{host_path} must use tier enforcement"
            );
            let tcp = config
                .global
                .telemetry
                .grpc_tcp
                .as_ref()
                .unwrap_or_else(|| panic!("{host_path} must configure gRPC TCP"));
            assert_eq!(
                tcp.token_file.as_deref(),
                expected_token_path.to_str(),
                "{host_path} must load the mounted test-only token"
            );
            assert_eq!(
                tcp.principal.as_deref(),
                Some(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
                "{host_path} must use the shared test-only principal"
            );
            assert_eq!(
                config
                    .security
                    .grpc
                    .roles
                    .get(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
                Some(&GrpcRoleConfig::Operator),
                "{host_path} test-only principal must be an operator"
            );
        }

        let driver_source = fs::read_to_string(interop.join("scripts").join(driver_name))
            .unwrap_or_else(|err| panic!("failed to read {driver_name}: {err}"));
        assert_eq!(
            driver_source
                .lines()
                .filter(|line| *line == "INTEROP_TEST_OPERATOR_AUTH=1")
                .count(),
            1,
            "{driver_name} must opt into shared test-only grpcurl authentication"
        );
        assert!(
            !driver_source.contains("grpcurl -plaintext"),
            "{driver_name} must route direct grpcurl calls through grpcurl_call"
        );
    }
    assert_eq!(
        config_count, 32,
        "the frozen M3-M32 and M34-M35c slice must cover 32 active configs"
    );

    for (label, config_name, topology_name) in [
        ("M0 FRR", "rustbgpd-frr.toml", "m0-frr.clab.yml"),
        ("M0 BIRD", "rustbgpd-bird.toml", "m0-bird.clab.yml"),
    ] {
        let source = fs::read_to_string(interop.join("configs").join(config_name))
            .unwrap_or_else(|err| panic!("failed to read {config_name}: {err}"));
        let config = parse_strict(&source)
            .unwrap_or_else(|err| panic!("{label} must validate under tier enforcement: {err}"));
        assert_eq!(
            config.security.grpc.enforcement,
            GrpcEnforcementConfig::Tier,
            "{label} must use tier enforcement"
        );
        let uds = config
            .global
            .telemetry
            .grpc_uds
            .as_ref()
            .unwrap_or_else(|| panic!("{label} must configure an explicit gRPC UDS"));
        assert_eq!(
            uds.principal.as_deref(),
            Some(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
            "{label} must use the stable test-only principal"
        );
        assert_eq!(
            config
                .security
                .grpc
                .roles
                .get(TEST_ONLY_GRPC_OPERATOR_PRINCIPAL),
            Some(&GrpcRoleConfig::Operator),
            "{label} test-only principal must be an operator"
        );
        assert!(
            uds.token_file.is_none(),
            "{label} UDS needs no bearer token"
        );

        let topology_source = fs::read_to_string(interop.join(topology_name))
            .unwrap_or_else(|err| panic!("failed to read {topology_name}: {err}"));
        assert!(
            !topology_source.contains("grpc-test-only-operator.token"),
            "{topology_name} must not mount a token for its UDS-only listener"
        );
    }
}

/// LAN-437 load-bearing proof: removing any retained IANA snapshot row or
/// parent exception changes its table row; breaking `rpol_files` or the chain
/// reference makes the real example fail to load. The ordinary-global and
/// 6to4 controls turn red if the starter expands into a blanket bogon filter.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the complete dated registry snapshot stays visible as one load-bearing table"
)]
fn route_server_example_special_purpose_snapshot() {
    let config = route_server_example_config();
    let neighbor = config
        .neighbors
        .first()
        .expect("route-server example has a neighbor");
    let (import, _) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("route-server example policy chains resolve");
    let import = import.expect("route-server example has an import chain");
    let member = import
        .policies
        .iter()
        .find(|member| member.name.as_deref() == Some("reject-special-purpose"))
        .expect("resolved import chain contains reject-special-purpose")
        .clone();
    let compiled = member
        .rpol
        .as_ref()
        .expect("special-purpose policy is .rpol-backed")
        .clone();
    let special_purpose = rustbgpd_policy::PolicyChain::from_named(vec![member]);

    let report = config.policy.rpol.policies["reject-special-purpose"]
        .file
        .run_tests();
    assert!(
        report.all_passed(),
        "route-server in-language policy tests failed: {:?}",
        report.failures
    );

    let rejected = [
        ("0.0.0.0/0", None, None, "0.0.0.0/0"),
        ("0.0.0.0/8", None, Some(32), "0.1.0.0/16"),
        ("10.0.0.0/8", None, Some(32), "10.1.0.0/16"),
        ("100.64.0.0/10", None, Some(32), "100.65.0.0/24"),
        ("127.0.0.0/8", None, Some(32), "127.1.0.0/16"),
        ("169.254.0.0/16", None, Some(32), "169.254.1.0/24"),
        ("172.16.0.0/12", None, Some(32), "172.17.0.0/16"),
        ("192.0.0.0/24", None, Some(32), "192.0.0.128/25"),
        ("192.0.2.0/24", None, Some(32), "192.0.2.0/25"),
        ("192.88.99.2/32", None, None, "192.88.99.2/32"),
        ("192.168.0.0/16", None, Some(32), "192.168.1.0/24"),
        ("198.18.0.0/15", None, Some(32), "198.18.1.0/24"),
        ("198.51.100.0/24", None, Some(32), "198.51.100.0/25"),
        ("203.0.113.0/24", None, Some(32), "203.0.113.0/25"),
        ("240.0.0.0/4", None, Some(32), "250.0.0.0/8"),
        ("::/0", None, None, "::/0"),
        ("::/128", None, None, "::/128"),
        ("::1/128", None, None, "::1/128"),
        ("::ffff:0:0/96", None, Some(128), "::ffff:192.0.2.0/120"),
        ("64:ff9b:1::/48", None, Some(128), "64:ff9b:1:1::/64"),
        ("100::/64", None, Some(128), "100::/65"),
        ("100:0:0:1::/64", None, Some(128), "100:0:0:1::/65"),
        ("2001::/23", None, Some(128), "2001:100::/32"),
        ("2001:db8::/32", None, Some(128), "2001:db8:1::/48"),
        ("3fff::/20", None, Some(128), "3fff:1::/32"),
        ("5f00::/16", None, Some(128), "5f00:1::/32"),
        ("fc00::/7", None, Some(128), "fd00:1::/48"),
        ("fe80::/10", None, Some(128), "fe80:1::/64"),
    ];
    assert_route_server_prefix_set(&compiled, "non-global-special-purpose", &rejected);
    for (prefix, _, _, probe) in rejected {
        let context = route_server_test_context(
            route_server_test_prefix(probe),
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
        );
        let (result, evaluation) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&special_purpose), &context);
        assert_eq!(
            result.action,
            rustbgpd_policy::PolicyAction::Deny,
            "retained snapshot row {prefix} must be rejected"
        );
        assert_eq!(
            evaluation.matched_policy.as_deref(),
            Some("reject-special-purpose"),
            "retained snapshot row {prefix} must attribute the rejection"
        );
    }

    let exceptions = [
        ("192.0.0.9/32", None, None, "192.0.0.9/32"),
        ("192.0.0.10/32", None, None, "192.0.0.10/32"),
        ("2001::/32", None, Some(128), "2001:0:1234::/48"),
        ("2001:1::1/128", None, None, "2001:1::1/128"),
        ("2001:1::2/128", None, None, "2001:1::2/128"),
        ("2001:1::3/128", None, None, "2001:1::3/128"),
        ("2001:3::/32", None, Some(128), "2001:3:1234::/48"),
        ("2001:4:112::/48", None, Some(128), "2001:4:112::1/128"),
        ("2001:20::/28", None, Some(128), "2001:20:abcd::/48"),
        ("2001:30::/28", None, Some(128), "2001:30:abcd::/48"),
    ];
    assert_route_server_prefix_set(&compiled, "special-purpose-parent-exceptions", &exceptions);
    for (prefix, _, _, probe) in exceptions {
        let context = route_server_test_context(
            route_server_test_prefix(probe),
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
        );
        let (result, _) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&special_purpose), &context);
        assert_eq!(
            result.action,
            rustbgpd_policy::PolicyAction::Permit,
            "active child {prefix} must precede and escape its rejected parent"
        );
    }

    for prefix in ["8.8.8.0/24", "2001:4860::/32", "2002::/16"] {
        let context = route_server_test_context(
            route_server_test_prefix(prefix),
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
        );
        let (result, _) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&special_purpose), &context);
        assert_eq!(
            result.action,
            rustbgpd_policy::PolicyAction::Permit,
            "out-of-snapshot control {prefix} must fall through"
        );
    }
}

/// LAN-437 load-bearing proof: the exact chain order keeps RPKI and ASPA
/// rejection ahead of parent exceptions and prefix-length caps after them.
/// Removing or reordering any member makes its attributed case fail; removing
/// the special-purpose member makes the representative/default cases permit.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one explicit matrix pins every ordered route-server import guard"
)]
fn route_server_example_exception_chain_preserves_later_guards() {
    let config = route_server_example_config();
    let neighbor = config
        .neighbors
        .first()
        .expect("route-server example has a neighbor");
    let (import, _) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("route-server example policy chains resolve");
    let import = import.expect("route-server example has an import chain");
    assert_eq!(
        import
            .policies
            .iter()
            .map(|member| member.name.as_deref().expect("every member is named"))
            .collect::<Vec<_>>(),
        [
            "reject-rpki-invalid",
            "ixp-hygiene",
            "reject-special-purpose",
            "reject-long-prefixes",
            "prefer-rpki-valid",
        ]
    );

    let cases = [
        (
            "0.0.0.0/0",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "::/0",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "100.65.0.0/24",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "fd00:1::/48",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-special-purpose",
            None,
        ),
        (
            "2001:4:112::/48",
            rustbgpd_wire::RpkiValidation::Invalid,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-rpki-invalid",
            None,
        ),
        (
            "2001::/32",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Invalid,
            rustbgpd_policy::PolicyAction::Deny,
            "ixp-hygiene",
            None,
        ),
        (
            "192.0.0.9/32",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-long-prefixes",
            None,
        ),
        (
            "2001:4:112::1/128",
            rustbgpd_wire::RpkiValidation::NotFound,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Deny,
            "reject-long-prefixes",
            None,
        ),
        (
            "2001:4:112::/48",
            rustbgpd_wire::RpkiValidation::Valid,
            rustbgpd_wire::AspaValidation::Unknown,
            rustbgpd_policy::PolicyAction::Permit,
            "prefer-rpki-valid",
            Some(200),
        ),
    ];
    for (prefix, rpki, aspa, action, matched_policy, local_pref) in cases {
        let context = route_server_test_context(route_server_test_prefix(prefix), rpki, aspa);
        let (result, evaluation) =
            rustbgpd_policy::evaluate_chain_with_attribution(Some(&import), &context);
        assert_eq!(result.action, action, "unexpected decision for {prefix}");
        assert_eq!(
            evaluation.matched_policy.as_deref(),
            Some(matched_policy),
            "unexpected deciding policy for {prefix}"
        );
        assert_eq!(
            result.modifications.set_local_pref, local_pref,
            "unexpected local-pref modification for {prefix}"
        );
    }
}

#[test]
fn m49_interop_configs_describe_preference_df_with_dont_preempt() {
    // Pin the M49 interop fixtures: PE1 (pref 100, revertive) and PE2 (pref
    // 200, non-revertive) both run highest-preference. Guards the smoke against
    // drift in the configs or the DF config surface.
    let pe1 = parse_with_shared_test_grpc_token(include_str!(
        "../../../tests/interop/configs/rustbgpd-m49-pe1.toml"
    ))
    .unwrap();
    let s1 = pe1.resolve_ethernet_segments().unwrap();
    assert_eq!(s1[0].df_algorithm, DfAlgorithm::HighestPreference);
    assert_eq!(s1[0].df_preference, 100);
    assert!(!s1[0].df_dont_preempt);

    let pe2 = parse_with_shared_test_grpc_token(include_str!(
        "../../../tests/interop/configs/rustbgpd-m49-pe2.toml"
    ))
    .unwrap();
    let s2 = pe2.resolve_ethernet_segments().unwrap();
    assert_eq!(s2[0].df_algorithm, DfAlgorithm::HighestPreference);
    assert_eq!(s2[0].df_preference, 200);
    assert!(s2[0].df_dont_preempt);
}

#[test]
fn m51_interop_config_describes_non_strict_bfd_with_fast_profile() {
    // Pin the M51 interop fixture: a single eBGP neighbor with non-strict BFD on
    // a "fast" 300/300/3 profile (detection ≈ 900 ms) and a 90 s BGP hold timer.
    // Guards the smoke against drift in the config or the BFD config surface —
    // the whole point of M51 is that a BFD-down failover beats the hold timer.
    let config = parse_with_shared_test_grpc_token(include_str!(
        "../../../tests/interop/configs/rustbgpd-m51-bfd.toml"
    ))
    .unwrap();
    let profile = &config.bfd_profiles[0];
    assert_eq!(profile.name, "fast");
    assert_eq!(profile.min_tx_interval, 300);
    assert_eq!(profile.min_rx_interval, 300);
    assert_eq!(profile.multiplier, 3);

    let n = config
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.2")
        .unwrap();
    assert_eq!(n.hold_time, Some(90));
    let bfd = n.bfd.as_ref().unwrap();
    assert_eq!(bfd.profile, "fast");
    assert!(bfd.enabled);
    assert!(!bfd.strict);
}

#[test]
fn m52_interop_config_enables_multipath_relax_with_mixed_asns() {
    // Pin the M52 interop fixture: multipath_relax on, maximum_paths 2, and two
    // neighbors in *different* ASes (65002 / 65003) — the whole point of the
    // smoke is that only multipath-relax co-installs the equal-length,
    // different-AS paths.
    let config = parse_with_shared_test_grpc_token(include_str!(
        "../../../tests/interop/configs/rustbgpd-m52-fib-ecmp-relax.toml"
    ))
    .unwrap();
    assert!(config.global.multipath_relax);
    assert_eq!(config.fib_tables[0].maximum_paths, Some(2));
    let asns: Vec<u32> = config.neighbors.iter().map(|n| n.remote_asn).collect();
    assert_eq!(asns, vec![65002, 65003], "peers must be in different ASes");
}

#[test]
fn m55_interop_config_pins_role_matrix_and_strict_neighbor() {
    // Pin the M55 interop fixture: it needs three compatible role pairs, one
    // incompatible Provider/Provider pair, one strict-role/no-remote-role peer,
    // and one raw Customer fixture for deliberate OTC leak injection.
    let config = parse_with_shared_test_grpc_token(include_str!(
        "../../../tests/interop/configs/rustbgpd-m55-bgp-roles-otc.toml"
    ))
    .unwrap();
    let roles: Vec<(String, u32, Option<BgpRole>, Option<bool>)> = config
        .neighbors
        .iter()
        .map(|n| {
            (
                n.address.clone(),
                n.remote_asn,
                n.role.map(BgpRoleConfig::to_wire),
                n.strict_role,
            )
        })
        .collect();
    assert_eq!(
        roles,
        vec![
            (
                "10.55.1.2".to_string(),
                65002,
                Some(BgpRole::Provider),
                None,
            ),
            (
                "10.55.2.2".to_string(),
                65003,
                Some(BgpRole::RouteServer),
                None,
            ),
            ("10.55.3.2".to_string(), 65004, Some(BgpRole::Peer), None),
            (
                "10.55.4.2".to_string(),
                65005,
                Some(BgpRole::Provider),
                None,
            ),
            (
                "10.55.5.2".to_string(),
                65006,
                Some(BgpRole::Provider),
                Some(true),
            ),
            (
                "10.55.6.2".to_string(),
                65007,
                Some(BgpRole::Provider),
                None,
            ),
        ]
    );
}

#[test]
fn config_knob_contributor_guide_pins_required_review_surfaces() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/config-knob-contributor-guide.md");
    let guide = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "could not read {} for config-knob guide structural test: {err}",
            path.display()
        )
    });
    for required in [
        "src/config/schema.rs",
        "src/config/validation.rs",
        "docs/reload-matrix.md",
        "RELOAD_MATRIX_NEIGHBOR_FIELDS",
        "RELOAD_MATRIX_PEER_GROUP_FIELDS",
        "docs/CONFIGURATION.md",
        "persist",
    ] {
        assert!(
            guide.contains(required),
            "config knob contributor guide must mention {required:?}"
        );
    }
}

/// The committed JSON Schema must stay in sync with the config structs.
/// `BLESS=1` rewrites the committed file (review the diff), mirroring the
/// diff-golden convention.
#[test]
fn config_json_schema_committed_copy_is_fresh() {
    let generated = config_json_schema();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/rustbgpd.schema.json");
    if std::env::var_os("BLESS").is_some() {
        fs::write(path, &generated).unwrap();
    }
    let committed = fs::read_to_string(path).unwrap();
    assert_eq!(
        generated, committed,
        "docs/rustbgpd.schema.json is stale — regenerate with `cargo run --bin rustbgpd -- \
         --dump-config-schema > docs/rustbgpd.schema.json` (or rerun this test with BLESS=1)"
    );
}
