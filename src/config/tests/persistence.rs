use super::*;

#[test]
fn config_round_trips_through_toml() {
    let config = parse(valid_toml()).unwrap();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let reloaded: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(config, reloaded);
}

#[test]
fn runtime_snapshot_token_is_stable_and_changes_with_config() {
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.global.honor_graceful_shutdown = !new.global.honor_graceful_shutdown;

    // Same key + same config => same token; same key + changed config => differs.
    let key = RuntimeSnapshotKey::random();
    let token_a = key.token(&old).unwrap();
    let token_b = key.token(&old).unwrap();
    let token_c = key.token(&new).unwrap();

    assert_eq!(token_a, token_b);
    assert_ne!(token_a, token_c);
    assert!(token_a.starts_with("kv1:"));
}

#[test]
fn persisted_config_sorts_every_hash_map_and_round_trips_to_a_fixpoint() {
    use sha2::{Digest as _, Sha256};

    // Load-bearing: every pair has reverse insertion and provably distinct raw
    // iteration order. Removing any serialize_with link makes the bytes differ.
    let (left, right) = reverse_insertion_persistence_pair();
    let left_document = persisted_config_document(&left).unwrap();
    let right_document = persisted_config_document(&right).unwrap();
    assert_eq!(left_document, right_document);
    assert_eq!(
        Sha256::digest(left_document.as_bytes()),
        Sha256::digest(right_document.as_bytes())
    );

    let reloaded: Config = toml::from_str(&left_document).unwrap();
    assert_eq!(persisted_config_document(&reloaded).unwrap(), left_document);
    let statements = &reloaded.policy.definitions["zeta"].statements;
    assert_eq!(statements[0].action, "permit");
    assert_eq!(statements[1].action, "deny");
}

#[test]
fn bounded_persistence_matches_oracle_for_every_statement_lane_and_boundary() {
    use sha2::{Digest as _, Sha256};

    let mut config = persistence_order_fixture(true, 0);
    let mut statement = parse_schema_only(&format!(
        "{}\n[policy.definitions.seed]\n[[policy.definitions.seed.statements]]\n\
         action = \"permit\"\nprefix = \"2001:db8::/32\"\nge = 48\n\
         match_community = [\"65001:7\"]\nset_community_add = [\"NO_EXPORT\"]\n\
         [policy.definitions.seed.statements.set_as_path_prepend]\nasn = 65001\ncount = 2\n",
        valid_toml()
    ))
    .unwrap()
    .policy
    .definitions
    .remove("seed")
    .unwrap()
    .statements
    .remove(0);
    statement.set_med = Some(0);

    config.neighbors[0].import_policy = vec![statement.clone()];
    config.neighbors[0].export_policy = vec![statement.clone(); 256];
    config.peer_groups.insert(
        "plain".to_string(),
        PeerGroupConfig {
            import_policy: vec![statement.clone(); 257],
            ..PeerGroupConfig::default()
        },
    );
    config.peer_groups.insert(
        "dotted.key \"雪\"".to_string(),
        PeerGroupConfig {
            export_policy: vec![statement.clone()],
            ..PeerGroupConfig::default()
        },
    );
    config.policy.definitions.insert(
        "quoted.\"policy\".雪".to_string(),
        NamedPolicyConfig {
            default_action: "deny".to_string(),
            statements: vec![statement],
        },
    );

    let original = config.clone();
    let oracle = persisted_config_document(&config).unwrap();
    let (bounded, stats) = super::canonical::render_document_bounded(&mut config).unwrap();
    assert_eq!(config, original, "the RAII guard must restore every lane");
    assert_eq!(bounded, oracle);
    assert_eq!(
        Sha256::digest(bounded.as_bytes()),
        Sha256::digest(oracle.as_bytes())
    );
    assert_eq!(stats.neighbor_import_lanes, 1);
    assert_eq!(stats.neighbor_export_lanes, 1);
    assert_eq!(stats.peer_group_import_lanes, 1);
    assert_eq!(stats.peer_group_export_lanes, 1);
    assert_eq!(stats.named_policy_lanes, 1);
    assert_eq!(stats.statements, 516);
    assert_eq!(stats.max_chunk_statements, 256);
    assert!(stats.max_chunk_bytes > 0);
    assert_eq!(bounded.matches(PERSISTED_CONFIG_HEADER).count(), 1);
    let reloaded: Config = toml::from_str(&bounded).unwrap();
    assert_eq!(persisted_config_document(&reloaded).unwrap(), bounded);
}

#[test]
fn bounded_persistence_error_restores_exact_config_and_token_body() {
    let mut config = persistence_order_fixture(false, 2);
    config.neighbors[0].import_policy = config.policy.definitions["zeta"].statements.clone();
    let original = config.clone();
    let error = super::canonical::render_document_bounded_with_test_hook(&mut config, |phase| {
        if phase == "before-statement-chunk" {
            Err(<toml::ser::Error as serde::ser::Error>::custom(
                "injected bounded-writer failure",
            ))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected bounded-writer failure")
    );
    assert_eq!(config, original);

    let key = RuntimeSnapshotKey::random();
    let context = [7_u8; 8];
    let document = persisted_config_document_bounded(&mut config).unwrap();
    assert_eq!(
        key.token_with_normalized_document(&document, &context)
            .unwrap(),
        key.token_with_context(&config, &context).unwrap()
    );
    assert_eq!(config, original);
    assert!(
        key.token_with_normalized_document("config_epoch = 1\n", &context)
            .unwrap_err()
            .contains("maintenance header")
    );
}

#[test]
fn production_persisted_document_roster_uses_only_the_bounded_writer() {
    for (name, source, expected) in [
        (
            "source_provenance",
            include_str!("../source_provenance.rs"),
            5,
        ),
        (
            "confirm_journal_v3",
            include_str!("../../confirm_journal/v3.rs"),
            2,
        ),
        (
            "peer_manager_reconcile",
            include_str!("../../peer_manager/reconcile.rs"),
            1,
        ),
    ] {
        assert_eq!(
            source.matches("persisted_config_document_bounded").count(),
            expected,
            "{name}"
        );
        assert!(!source.contains("persisted_config_document("), "{name}");
    }
}

/// Every canonical sink materializes the effective epoch and policy through
/// one borrowed renderer, while the accepted boot file stays byte-identical.
/// Bypassing the renderer at any sink makes an equality/presence assertion red.
#[test]
fn rfc8212_canonical_sinks_materialize_without_rewriting_boot_input() {
    let raw_source = tier_authorized_uds_test_config(valid_toml());
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), &raw_source).unwrap();
    let raw = Config::load_with_diagnostics(file.path().to_str().unwrap()).unwrap();
    assert_eq!(fs::read_to_string(file.path()).unwrap(), raw_source);
    assert_eq!(raw.config_epoch, None);
    assert_eq!(raw.global.ebgp_requires_policy, None);

    let explicit = parse(&rfc8212_representation_toml(Some("1"), Some(false))).unwrap();
    let persisted = persisted_config_document(&raw).unwrap();
    assert!(persisted.contains("config_epoch = 1"), "{persisted}");
    assert!(
        persisted.contains("ebgp_requires_policy = false"),
        "{persisted}"
    );
    let reloaded = Config::load_toml_with_diagnostics(&persisted, "canonical persisted").unwrap();
    assert_eq!(persisted_config_document(&reloaded).unwrap(), persisted);

    let key = RuntimeSnapshotKey::random();
    assert_eq!(key.token(&raw).unwrap(), key.token(&explicit).unwrap());
    assert_eq!(
        raw.effective_redacted_toml().unwrap(),
        explicit.effective_redacted_toml().unwrap()
    );
}

/// Load-bearing transaction matrix. Removing the supported-mutation fence,
/// accepting a partial/source-regressing tuple, or changing the exact
/// canonical target makes a named row red.
#[test]
fn rfc8212_transaction_materialization_requires_real_mutation_and_exact_posture() {
    for (label, live_epoch, live_policy, candidate_epoch, candidate_policy) in [
        ("raw legacy", None, None, None, None),
        ("caller canonical", None, None, Some("1"), Some(false)),
        ("true posture", None, Some(true), None, Some(true)),
        ("epoch-only omission", Some("1"), None, Some("1"), None),
    ] {
        let live = rfc8212_transaction_fixture(live_epoch, live_policy, false);
        let mut candidate = rfc8212_transaction_fixture(candidate_epoch, candidate_policy, true);
        let operational = materialize_rfc8212_transaction_candidate(&live, &mut candidate)
            .unwrap_or_else(|| panic!("{label} must materialize"));
        assert_eq!(
            classify_config_transaction_v1(&operational).supported_sections,
            vec!["[[neighbors]] add"],
            "{label}"
        );
        let posture = candidate.rfc8212_posture();
        assert_eq!(posture.config_epoch_raw, Some(ConfigEpoch::V1), "{label}");
        assert_eq!(
            posture.policy_raw,
            Some(posture.policy_effective),
            "{label}"
        );
    }

    for (label, live_epoch, live_policy, candidate_epoch, candidate_policy, mutate) in [
        ("no-op", None, None, None, None, false),
        ("representation", None, None, Some("1"), Some(false), false),
        ("partial", None, None, Some("1"), None, true),
        ("effective change", None, None, None, Some(true), true),
        (
            "source regression",
            Some("1"),
            Some(false),
            None,
            None,
            true,
        ),
        ("epoch move", None, None, Some("2"), Some(false), true),
    ] {
        let live = rfc8212_transaction_fixture(live_epoch, live_policy, false);
        let mut candidate = rfc8212_transaction_fixture(candidate_epoch, candidate_policy, mutate);
        let before = candidate.rfc8212_posture();
        assert!(
            materialize_rfc8212_transaction_candidate(&live, &mut candidate).is_none(),
            "{label}"
        );
        assert_eq!(candidate.rfc8212_posture(), before, "{label}");
    }
}

/// Structural companion to the release HWM receipt: the runtime A/B alone
/// cannot detect adding the same internal deep clone to both arms. This pins
/// every large projection field as borrowed, only small Global/map-key clones,
/// and direct serialization (no whole-tree `toml::Value`).
#[test]
fn canonical_projection_borrows_every_large_config_field() {
    let source = include_str!("../canonical.rs");
    for field in [
        "security: &'a SecurityConfig",
        "neighbors: &'a [Neighbor]",
        "peer_groups: &'a std::collections::HashMap",
        "policy: &'a PolicyConfig",
        "dynamic_neighbors: &'a [DynamicNeighborConfig]",
        "evpn_instances: &'a [EvpnInstanceConfig]",
        "ethernet_segments: &'a [EthernetSegmentConfig]",
        "evpn_ip_vrfs: &'a [EvpnIpVrfConfig]",
        "fib_tables: &'a [FibTableConfig]",
        "managed_netdevs: &'a ManagedNetdevsConfig",
        "bfd_profiles: &'a [BfdProfileConfig]",
    ] {
        assert!(source.contains(field), "canonical projection lost {field}");
    }
    assert_eq!(source.matches("name.clone()").count(), 3, "{source}");
    assert_eq!(source.matches(".clone()").count(), 4, "{source}");
    assert!(source.contains("let mut canonical_global = global.clone()"));
    assert!(!source.contains("toml::Value::try_from"), "{source}");
    assert!(source.contains("toml::to_string_pretty(&CanonicalConfig::from(config))"));
}

#[cfg(target_os = "linux")]
#[test]
fn persistence_probe_comparison_rejects_vacuous_sorted_hwm() {
    // Load-bearing: replacing the two per-arm growth assertions with `||`
    // makes the zero-growth sorted receipt pass and this test fail.
    let direct = [342_422_054, 2_500_000_000, 0, 0, 1_740_000_000];
    let sorted = [342_422_054, 2_500_000_000, 0, 0, 0];
    assert!(
        std::panic::catch_unwind(|| assert_persistence_probe_receipts(&direct, &sorted)).is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn persistence_probe_comparison_rejects_owned_sized_borrowed_projection() {
    let borrowed = [342_422_054, 2_500_000_000, 0, 0, 1_740_000_000, 0];
    let owned = [342_422_054, 2_500_000_000, 0, 0, 1_740_000_000, 1];
    assert!(
        std::panic::catch_unwind(|| {
            assert_borrowed_persistence_probe_receipts(&borrowed, "same", &owned, "same");
        })
        .is_err()
    );
}

#[test]
fn bounded_writer_candidate_receipt_is_load_bearing() {
    let receipt = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/perf/artifacts/persisted-config-serialization-2026-08/candidate.tsv"
    ));
    verify_bounded_writer_receipt(receipt);
    let invalid = receipt.replacen("\t256\n", "\t257\n", 1);
    assert!(std::panic::catch_unwind(|| verify_bounded_writer_receipt(&invalid)).is_err());
}

#[test]
fn persisted_config_phase_receipt_is_load_bearing() {
    let control = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/perf/artifacts/persisted-config-serialization-2026-08/control.tsv"
    ));
    assert_eq!(
        verify_persistence_phase_receipt(control),
        PersistencePhaseDecision::Go
    );
    let edited = |edit: fn(&mut Vec<Vec<String>>)| {
        let mut rows: Vec<_> = control
            .lines()
            .map(|line| line.split('\t').map(str::to_owned).collect())
            .collect();
        edit(&mut rows);
        rows.into_iter()
            .map(|row| row.join("\t"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let invalid = |edit| {
        let source = edited(edit);
        assert!(std::panic::catch_unwind(|| verify_persistence_phase_receipt(&source)).is_err());
    };
    invalid(|rows| {
        rows.remove(4);
    });
    invalid(|rows| rows[1][10] = "0".into());
    invalid(|rows| rows[1][5] = "319".into());
    invalid(|rows| rows.retain(|row| row[0] != "6"));
    invalid(|rows| rows[1][9] = "0".repeat(64));
    let no_go = edited(|rows| {
        for (production, rendered, graph, header) in
            [(2, 5, 6, 7), (14, 10, 11, 12), (16, 19, 20, 21)]
        {
            let resident = rows[graph][12].clone();
            let rss = rows[graph][13].clone();
            let peak = rows[rendered][14].clone();
            rows[header][12] = resident;
            rows[header][13] = rss;
            rows[header][14] = peak.clone();
            rows[production][14] = peak;
        }
    });
    assert_eq!(
        verify_persistence_phase_receipt(&no_go),
        PersistencePhaseDecision::NoGo
    );
    let noisy = edited(|rows| rows[3][11] = "1400000000".into());
    assert_eq!(
        verify_persistence_phase_receipt(&noisy),
        PersistencePhaseDecision::Inconclusive
    );
    let dir = tempfile::tempdir().unwrap();
    retain_persistence_phase_receipt(&dir.path().join("receipt.tsv"), control);
}

/// The maintenance header belongs to files the daemon writes, and nowhere
/// else. Two neighbouring canonical renderings sit right next to the persist
/// path and must stay clean of it: the commit-confirm snapshot token and the
/// `GetEffectiveConfig` response body, which is an API payload, not a file.
///
/// The header is inert comment text, so everything derived from a persisted
/// file must be identical to the same thing derived from a header-free
/// rendering — a header that stopped being inert, or that leaked into a
/// derived surface, shows up here.
#[test]
fn persisted_config_header_stays_out_of_the_token_and_the_effective_dump() {
    let config = parse(valid_toml()).unwrap();
    let document = persisted_config_document(&config).unwrap();
    assert!(document.starts_with(PERSISTED_CONFIG_HEADER));

    let bare = toml::to_string_pretty(&config).unwrap();
    assert!(
        !bare.contains("maintained by rustbgpd"),
        "the bare canonical rendering must carry no header"
    );

    // Same config, one document with the header and one without. Everything
    // downstream must agree.
    let from_persisted = Config::load_toml_with_diagnostics(&document, "persisted.toml")
        .expect("the header must stay inert TOML that the loader ignores");
    let from_bare = Config::load_toml_with_diagnostics(&bare, "bare.toml").unwrap();

    let key = RuntimeSnapshotKey::random();
    assert_eq!(
        key.token(&from_persisted).unwrap(),
        key.token(&from_bare).unwrap(),
        "the snapshot token must follow the config, not the document it was read from"
    );

    let effective = from_persisted.effective_redacted_toml().unwrap();
    assert_eq!(
        effective,
        from_bare.effective_redacted_toml().unwrap(),
        "the effective dump must not vary with the file header"
    );
    assert!(
        !effective.contains("maintained by rustbgpd"),
        "the effective-config API response must not carry the file header:\n{effective}"
    );
}

#[test]
fn policy_statement_empty_community_lists_round_trip_to_compact_toml() {
    // Destructive proof: removing `skip_serializing_if` from any of the three
    // default-empty vectors makes its persisted-document absence assertion
    // red; dropping `default` makes the compact Config round trip fail;
    // skipping a non-empty value makes the preservation assertions red.
    let legacy_explicit_empty = format!(
        "{}{}",
        valid_toml(),
        r#"
[[neighbors.import_policy]]
action = "permit"
prefix = "192.0.2.0/24"
match_community = []
set_community_add = []
set_community_remove = []
"#
    );
    let config = parse(&legacy_explicit_empty).unwrap();
    let compact = persisted_config_document(&config).unwrap();
    for field in [
        "match_community",
        "set_community_add",
        "set_community_remove",
    ] {
        assert!(!compact.contains(field), "{field} leaked into:\n{compact}");
    }
    let compact_reloaded =
        Config::load_toml_with_diagnostics(&compact, "compacted persisted config").unwrap();
    assert_eq!(
        persisted_config_document(&compact_reloaded).unwrap(),
        compact,
        "old explicit-empty input must reach the canonical fixpoint"
    );

    let populated = parse(&format!(
        "{}{}",
        valid_toml(),
        r#"
[[neighbors.import_policy]]
action = "permit"
prefix = "192.0.2.0/24"
match_community = ["65001:100"]
set_community_add = ["NO_EXPORT"]
set_community_remove = ["BLACKHOLE"]
"#
    ))
    .unwrap();
    let populated_toml = persisted_config_document(&populated).unwrap();
    assert!(populated_toml.contains("match_community = [\"65001:100\"]"));
    assert!(populated_toml.contains("set_community_add = [\"NO_EXPORT\"]"));
    assert!(populated_toml.contains("set_community_remove = [\"BLACKHOLE\"]"));
    let populated_reloaded =
        Config::load_toml_with_diagnostics(&populated_toml, "populated persisted config").unwrap();
    assert_eq!(
        persisted_config_document(&populated_reloaded).unwrap(),
        populated_toml
    );
}

#[test]
fn runtime_snapshot_token_changes_when_only_a_secret_rotates() {
    // The token hashes the full config, secrets included, so a bare secret
    // rotation still invalidates a stale optimistic-concurrency token (ADR-0076:
    // the token must change if any candidate-relevant config byte changes).
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].md5_password = Some("old-secret".to_string());
    let mut new = old.clone();
    new.neighbors[0].md5_password = Some("new-secret".to_string());

    let key = RuntimeSnapshotKey::random();
    assert_ne!(key.token(&old).unwrap(), key.token(&new).unwrap());
}

#[test]
fn runtime_snapshot_token_does_not_encode_config_length() {
    // The normalized rendering includes plaintext secrets, so its byte
    // length must not appear in the token: configs whose secrets differ
    // only in length yield same-shape, digest-only tokens.
    let mut short = parse(valid_toml()).unwrap();
    short.neighbors[0].md5_password = Some("s".to_string());
    let mut long = short.clone();
    long.neighbors[0].md5_password = Some("s".repeat(64));

    let key = RuntimeSnapshotKey::random();
    let token_short = key.token(&short).unwrap();
    let token_long = key.token(&long).unwrap();
    assert_eq!(token_short.len(), "kv1:".len() + 16, "{token_short}");
    assert_eq!(token_short.len(), token_long.len());
    assert_ne!(token_short, token_long);
}

#[test]
fn neighbor_and_peer_group_debug_redact_md5_password() {
    let mut config = parse(valid_toml()).unwrap();
    config.neighbors[0].md5_password = Some("hunter2-secret".to_string());
    let rendered = format!("{:?}", config.neighbors[0]);
    assert!(!rendered.contains("hunter2-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let group = PeerGroupConfig {
        md5_password: Some("hunter2-secret".to_string()),
        ..PeerGroupConfig::default()
    };
    let rendered = format!("{group:?}");
    assert!(!rendered.contains("hunter2-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn runtime_snapshot_token_differs_across_keys() {
    // The token is keyed: a caller who does not hold the per-process key cannot
    // reproduce the digest for a known config. That is what closes the
    // secret-guessing oracle — two independently seeded keys must disagree on
    // the same config.
    let config = parse(valid_toml()).unwrap();
    let key_a = RuntimeSnapshotKey::random();
    let key_b = RuntimeSnapshotKey::random();
    assert_ne!(key_a.token(&config).unwrap(), key_b.token(&config).unwrap());
}

#[test]
fn runtime_snapshot_token_canonicalizes_map_order() {
    let mut left = parse(valid_toml()).unwrap();
    let mut right = left.clone();

    left.security.grpc.roles.clear();
    left.security
        .grpc
        .roles
        .insert("operator.example".to_string(), GrpcRoleConfig::Operator);
    left.security
        .grpc
        .roles
        .insert("observer.example".to_string(), GrpcRoleConfig::Observer);

    right.security.grpc.roles.clear();
    right
        .security
        .grpc
        .roles
        .insert("observer.example".to_string(), GrpcRoleConfig::Observer);
    right
        .security
        .grpc
        .roles
        .insert("operator.example".to_string(), GrpcRoleConfig::Operator);

    // Map insertion order must not perturb the token (same key both sides).
    let key = RuntimeSnapshotKey::random();
    assert_eq!(key.token(&left).unwrap(), key.token(&right).unwrap());
}

// ---------------------------------------------------------------------------
// Effective running config dump (`rbgp config effective`, LAN-325)
// ---------------------------------------------------------------------------

#[test]
fn effective_redacted_materializes_neighbor_defaults() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
    let config =
        Config::load_toml_with_diagnostics(&tier_authorized_uds_test_config(toml_str), "test.toml")
            .unwrap();
    let rendered = config.effective_redacted_toml().unwrap();

    // Computed defaults appear as concrete values: DEFAULT_HOLD_TIME and
    // the RFC 9687 §6 derived send-hold default (max(480, 2 × hold)).
    assert!(rendered.contains("hold_time = 90"), "{rendered}");
    assert!(rendered.contains("send_hold_time = 480"), "{rendered}");
    assert!(rendered.contains("graceful_restart = true"), "{rendered}");
    assert!(
        rendered.contains("gr_peer_restart_time_max = 4095"),
        "{rendered}"
    );
    assert!(rendered.contains("gr_restart_time = 120"), "{rendered}");
    assert!(
        rendered.contains("gr_stale_routes_time = 360"),
        "{rendered}"
    );
    assert!(rendered.contains("llgr_stale_time = 0"), "{rendered}");
    assert!(rendered.contains("ttl_security = false"), "{rendered}");
    assert!(rendered.contains("\"ipv4_unicast\""), "{rendered}");
}

#[test]
fn effective_redacted_matches_resolve_neighbor() {
    // Drift guard: the materialization constants in `effective_redacted`
    // must agree with `resolve_neighbor` for both a bare neighbor and a
    // group-inheriting neighbor.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.rr-clients]
hold_time = 30
min_hold_time = 20
gr_restart_time = 200

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65001
peer_group = "rr-clients"
"#;
    let config =
        Config::load_toml_with_diagnostics(&tier_authorized_uds_test_config(toml_str), "test.toml")
            .unwrap();
    let effective = config.effective_redacted();
    for (original, materialized) in config.neighbors.iter().zip(&effective.neighbors) {
        let resolved = config.resolve_neighbor(original).unwrap();
        let peer = &resolved.transport_config.peer;
        assert_eq!(materialized.hold_time, Some(peer.hold_time));
        assert_eq!(materialized.min_hold_time, peer.min_hold_time);
        assert_eq!(materialized.send_hold_time, Some(peer.send_hold_time));
        assert_eq!(materialized.graceful_restart, Some(peer.graceful_restart));
        assert_eq!(materialized.gr_restart_time, Some(peer.gr_restart_time));
        assert_eq!(
            materialized.gr_peer_restart_time_max,
            Some(resolved.transport_config.gr_peer_restart_time_max)
        );
        assert_eq!(
            materialized.gr_stale_routes_time,
            Some(resolved.transport_config.gr_stale_routes_time)
        );
        assert_eq!(
            materialized.llgr_stale_time,
            Some(resolved.transport_config.llgr_stale_time)
        );
        assert_eq!(
            materialized.ttl_security,
            Some(resolved.transport_config.ttl_security)
        );
    }
    // Group inheritance visible on the second neighbor.
    assert_eq!(effective.neighbors[1].hold_time, Some(30));
    assert_eq!(effective.neighbors[1].gr_restart_time, Some(200));
}

#[test]
fn effective_redacted_never_leaks_secrets() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.md5-group]
md5_password = "group-hunter2-seed"

[peer_groups.dynamic]
hold_time = 90

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "dynamic"
tcp_ao = { key = "dynamic-hunter2-seed", send_id = 3, recv_id = 4, algorithm = "hmac(sha256)" }

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "neighbor-hunter2-seed"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003

[neighbors.tcp_ao]
key = "tcp-ao-hunter2-seed"
send_id = 1
recv_id = 2
algorithm = "hmac(sha256)"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65001
peer_group = "md5-group"
"#;
    let config =
        Config::load_toml_with_diagnostics(&tier_authorized_uds_test_config(toml_str), "test.toml")
            .unwrap();
    let rendered = config.effective_redacted_toml().unwrap();
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains(REDACTED_SECRET), "{rendered}");
}

#[test]
fn effective_redacted_toml_is_deterministic_and_round_trips() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.zeta]
hold_time = 15

[peer_groups.alpha]
hold_time = 45

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
peer_group = "alpha"

[[neighbors]]
address = "2001:db8::2"
remote_asn = 65002
"#;
    let config =
        Config::load_toml_with_diagnostics(&tier_authorized_uds_test_config(toml_str), "test.toml")
            .unwrap();
    let first = config.effective_redacted_toml().unwrap();
    let second = config.effective_redacted_toml().unwrap();
    assert_eq!(first, second, "effective dump must be deterministic");

    // Secretless dumps round-trip through the normal loader + validator.
    let reloaded = Config::load_toml_with_diagnostics(&first, "effective.toml")
        .expect("secretless effective dump must reload cleanly");
    assert_eq!(reloaded.neighbors[0].hold_time, Some(45));
    // Implicit-family default for the IPv6 neighbor is materialized.
    let v6 = reloaded
        .neighbors
        .iter()
        .find(|n| n.address == "2001:db8::2")
        .unwrap();
    assert_eq!(
        v6.families,
        vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()]
    );

    // Reloading the dump and dumping again is a fixpoint.
    assert_eq!(reloaded.effective_redacted_toml().unwrap(), first);
}

#[test]
fn redacted_placeholder_fails_validation_loudly() {
    for (label, snippet) in [
        (
            "neighbor md5",
            "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\nmd5_password = \"<redacted>\"\n",
        ),
        (
            "tcp_ao key",
            "[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n[neighbors.tcp_ao]\nkey = \"<redacted>\"\nsend_id = 1\nrecv_id = 2\nalgorithm = \"hmac(sha256)\"\n",
        ),
        (
            "peer group md5",
            "[peer_groups.g]\nmd5_password = \"<redacted>\"\n",
        ),
        (
            "dynamic tcp_ao key",
            "[peer_groups.g]\nhold_time = 90\n[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"g\"\ntcp_ao = { key = \"<redacted>\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }\n",
        ),
    ] {
        let toml_str = format!(
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n[global.telemetry]\nlog_format = \"json\"\n\n{snippet}"
        );
        let err = Config::load_toml_with_diagnostics(&toml_str, "effective.toml").expect_err(label);
        assert!(err.contains("rbgp config effective"), "{label}: {err}");
    }
}

#[test]
fn effective_redacted_dump_with_secrets_does_not_reload() {
    // The documented contract: a dump taken from a secret-bearing config
    // must fail --check/load loudly rather than boot with the placeholder.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "hunter2"
"#;
    let config =
        Config::load_toml_with_diagnostics(&tier_authorized_uds_test_config(toml_str), "test.toml")
            .unwrap();
    let rendered = config.effective_redacted_toml().unwrap();
    let err = Config::load_toml_with_diagnostics(&rendered, "effective.toml").unwrap_err();
    assert!(err.contains("md5_password"), "{err}");
}
