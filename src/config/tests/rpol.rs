use super::*;

#[test]
fn rpol_files_load_resolve_and_evaluate_in_chains() {
    let dir = rpol_config_dir(
        RPOL_SOURCE,
        r#""customer-in(200)", "bogon-filter", "toml-pass""#,
    );
    let config = load_dir(&dir).expect("config with rpol files loads");

    // Relative path rewritten absolute against the config dir.
    assert_eq!(config.policy.rpol_files.len(), 1);
    assert!(
        Path::new(&config.policy.rpol_files[0]).is_absolute(),
        "{:?}",
        config.policy.rpol_files[0]
    );
    assert_eq!(config.policy.rpol.policies.len(), 2);

    // Resolver equivalence: the neighbor's effective import chain
    // carries pre-compiled rpol members mixed with the TOML policy,
    // and routes flow / are denied per the policy through the same
    // chain-eval seam sessions use.
    let neighbor = &config.neighbors[0];
    let (import, _) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("chains resolve");
    let import = import.expect("import chain configured");
    assert_eq!(import.policies.len(), 3);
    assert_eq!(import.policies[0].name.as_deref(), Some("customer-in(200)"));
    assert!(import.policies[0].rpol.is_some());
    assert!(import.policies[2].rpol.is_none());

    let ctx = |prefix: Prefix| rustbgpd_policy::RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    let customer = Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        "10.10.3.0".parse().unwrap(),
        24,
    ));
    let bogon = Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        "127.0.0.0".parse().unwrap(),
        8,
    ));
    let (result, eval) =
        rustbgpd_policy::evaluate_chain_with_attribution(Some(&import), &ctx(customer));
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Permit);
    assert_eq!(result.modifications.set_local_pref, Some(200));
    assert_eq!(eval.matched_policy.as_deref(), Some("toml-pass"));
    let (result, eval) =
        rustbgpd_policy::evaluate_chain_with_attribution(Some(&import), &ctx(bogon));
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Deny);
    assert_eq!(eval.matched_policy.as_deref(), Some("bogon-filter"));
}

/// LAN-888: a config load emits one phase-attributed timing line
/// (`config source loaded` with `toml_parse_ms` / `rpol_load_ms` /
/// `dataset_bind_ms` / `validate_ms` nested inside `elapsed_ms`), and the
/// once-per-`RpolFile` set-table intern stamps its own line — so a SIGHUP
/// reload's daemon log attributes where load time went with no harness.
#[test]
fn config_load_emits_phase_timing_fields() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let sink = Sink(Arc::new(Mutex::new(Vec::new())));
    let writer_sink = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer_sink.clone())
        .finish();

    let dir = rpol_config_dir(RPOL_SOURCE, r#""customer-in(200)", "bogon-filter""#);
    tracing::subscriber::with_default(subscriber, || {
        // Sibling tests reach these callsites with no subscriber installed,
        // which caches `Interest::never()` process-wide, and a scoped
        // subscriber does not invalidate that cache. Warm the callsites, then
        // re-register them against this subscriber; a callsite is registered
        // once, so the measured load below cannot lose the race afterwards.
        drop(load_dir(&dir).expect("config with rpol files loads"));
        tracing::callsite::rebuild_interest_cache();
        sink.0.lock().unwrap().clear();

        let config = load_dir(&dir).expect("config with rpol files loads");
        // Chain resolution reaches the once-per-file set-table intern
        // regardless of whether validation already built it.
        config
            .effective_policy_chains_for_neighbor(&config.neighbors[0])
            .expect("chains resolve");
    });

    let output = String::from_utf8(sink.0.lock().unwrap().clone()).expect("utf8 log output");
    let loaded = output
        .lines()
        .find(|line| line.contains("config source loaded"))
        .unwrap_or_else(|| panic!("config load emits its timing line; captured: {output}"));
    let json: serde_json::Value = serde_json::from_str(loaded).expect("structured log line");
    let fields = &json["fields"];
    let phase = |name: &str| {
        fields[name]
            .as_u64()
            .unwrap_or_else(|| panic!("{name} must be a u64 field on: {loaded}"))
    };
    assert!(
        phase("toml_parse_ms")
            + phase("rpol_load_ms")
            + phase("dataset_bind_ms")
            + phase("validate_ms")
            <= phase("elapsed_ms"),
        "phase timings must nest inside the total: {loaded}"
    );
    assert!(
        output.contains("interned rpol set tables built"),
        "set-table intern build must stamp its own timing line"
    );
}

/// The real startup roster resolves neighbors through bounded set-interning
/// chunks. Common `.rpol` set content within one chunk must share its backing
/// index, distinct content must not alias, and allocation identity must remain
/// invisible to structural policy equality / reload planning.
///
/// Red proofs:
/// - restoring one `SetStore` per neighbor makes the within-chunk `ptr_eq` red;
/// - interning distinct set contents under one key makes the non-alias red;
/// - changing compiled-chain equality to allocation identity makes the
///   independently resolved equality and no-impact diff assertions red.
#[test]
fn resolved_neighbor_batch_shares_only_content_equal_rpol_sets() {
    let source = r"
prefix-set shared { 10.0.0.0/8 le 32, 192.0.2.0/24 }
prefix-set distinct { 198.51.100.0/24, 203.0.113.0/24 }

policy shared-import {
    term allow { if route.prefix in shared { accept } }
}
policy distinct-import {
    term allow { if route.prefix in distinct { accept } }
}
";
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), source).expect("write rpol");
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = ["shared-import"]

[[neighbors]]
address = "192.0.2.2"
remote_asn = 65003
import_policy_chain = ["shared-import"]

[[neighbors]]
address = "192.0.2.3"
remote_asn = 65004
import_policy_chain = ["distinct-import"]
"#;
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(toml),
    )
    .expect("write config");
    let config = load_dir(&dir).expect("sharing fixture loads");
    let resolved = config
        .resolved_neighbors()
        .expect("startup roster resolves");

    let named_set = |neighbor: &ResolvedNeighbor, name: &str| {
        let chain = neighbor.import_policy.as_ref().expect("import chain");
        let compiled = chain.policies[0].rpol.as_ref().expect("rpol member");
        let index = compiled
            .prefix_set_names
            .iter()
            .position(|candidate| candidate.as_deref() == Some(name))
            .expect("named set");
        std::sync::Arc::clone(&compiled.prefix_sets[index])
    };
    let first = named_set(&resolved[0], "shared");
    let second = named_set(&resolved[1], "shared");
    let distinct = named_set(&resolved[2], "distinct");
    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "content-equal sets in one resolved roster must share one index"
    );
    assert!(
        !std::sync::Arc::ptr_eq(&first, &distinct),
        "content-distinct sets must never alias"
    );

    let independently_resolved = config
        .resolve_neighbor(&config.neighbors[0])
        .expect("standalone resolution");
    assert_eq!(
        resolved[0].import_policy, independently_resolved.import_policy,
        "shared allocation identity must not change structural chain equality"
    );
    let unchanged = diff_config(&config, &config.clone());
    assert!(
        unchanged.effective_neighbor_impact.is_empty(),
        "allocation identity must not manufacture reload impact: {:?}",
        unchanged.effective_neighbor_impact
    );
}

/// Every resolved neighbor shares one canonical copy of an rpol set's
/// data, without changing neighbor order: the compiled unit interns
/// its sets once and every chain instantiation clones the `Arc`s
/// (LAN-788 — per-chunk re-interning gave 320 IRR-scale peers ten
/// independent multi-million-entry copies).
///
/// Red proofs:
/// - restoring per-chain interning (`Lowerer::new` re-interning
///   through the caller's store) makes the identity and
///   canonical-copy-count assertions red;
/// - reordering resolution output makes the address-order assertion
///   red.
#[test]
fn resolved_neighbor_set_sharing_is_global_and_ordered() {
    let source = r"
prefix-set shared { 10.0.0.0/8 le 32, 192.0.2.0/24 }
policy shared-import {
    term allow { if route.prefix in shared { accept } }
}
";
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), source).expect("write rpol");
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = ["shared-import"]
"#;
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(toml),
    )
    .expect("write config");
    let mut config = load_dir(&dir).expect("bounded-sharing fixture loads");
    let template = config.neighbors[0].clone();
    config.neighbors = (0..65)
        .map(|index| {
            let mut neighbor = template.clone();
            neighbor.address = format!("192.0.2.{}", index + 1);
            neighbor.remote_asn = 65_002 + index;
            neighbor
        })
        .collect();

    let resolved = config
        .resolved_neighbors()
        .expect("bounded roster resolves");
    let set = |neighbor: &ResolvedNeighbor| {
        std::sync::Arc::clone(
            &neighbor.import_policy.as_ref().unwrap().policies[0]
                .rpol
                .as_ref()
                .unwrap()
                .prefix_sets[0],
        )
    };
    assert!(std::sync::Arc::ptr_eq(
        &set(&resolved[0]),
        &set(&resolved[31])
    ));
    assert!(std::sync::Arc::ptr_eq(
        &set(&resolved[31]),
        &set(&resolved[32])
    ));
    let canonical_copies: std::collections::HashSet<_> = resolved
        .iter()
        .map(|neighbor| std::sync::Arc::as_ptr(&set(neighbor)))
        .collect();
    assert_eq!(
        canonical_copies.len(),
        1,
        "all 65 peers must share one canonical copy of the set data"
    );
    let actual_order: Vec<_> = resolved
        .iter()
        .map(|neighbor| neighbor.transport_config.remote_addr.ip().to_string())
        .collect();
    let expected_order: Vec<_> = config
        .neighbors
        .iter()
        .map(|neighbor| neighbor.address.clone())
        .collect();
    assert_eq!(actual_order, expected_order);
}

/// LAN-300: a config-referenced `.rpol` file resolves its `import`
/// graph — from its own directory and from `[policy] rpol_roots`
/// (rewritten absolute like `rpol_files`) — and a broken import
/// anywhere rejects the whole load (one atomic candidate per unit,
/// ADR-0103 Decision 8.1).
#[test]
fn rpol_imports_resolve_through_config_roots_and_fail_atomically() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::create_dir_all(dir.path().join("shared/lib")).expect("mkdir");
    fs::write(
        dir.path().join("shared/lib/bogons.rpol"),
        "prefix-set bogons { 127.0.0.0/8 le 32 }",
    )
    .expect("write lib");
    fs::write(
        dir.path().join("policies/core.rpol"),
        "import \"lib/bogons.rpol\"\n\
         policy edge-in { term bogon { if route.prefix in bogons { reject } } }",
    )
    .expect("write rpol");
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]
rpol_roots = ["shared"]
import_chain = ["edge-in"]
"#;
    fs::write(
        dir.path().join("config.toml"),
        tier_authorized_uds_test_config(toml),
    )
    .expect("write config");
    let config = load_dir(&dir).expect("config with rpol imports loads");
    // Roots rewritten absolute, like rpol_files.
    assert_eq!(config.policy.rpol_roots.len(), 1);
    assert!(Path::new(&config.policy.rpol_roots[0]).is_absolute());
    // The imported prefix-set participates in the compiled chain.
    let chain = config.import_chain().expect("resolves").expect("present");
    let ctx = rustbgpd_policy::RouteContext {
        prefix: Some(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            "127.0.0.1".parse().unwrap(),
            32,
        ))),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    let result = chain.evaluate(&ctx);
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Deny);

    // Break the imported leaf: the WHOLE config load is rejected —
    // no partial registry, and the diagnostic names the leaf file.
    fs::write(
        dir.path().join("shared/lib/bogons.rpol"),
        "prefix-set bogons { not-a-prefix }",
    )
    .expect("rewrite lib");
    let err = load_dir(&dir).expect_err("broken import rejects the load");
    assert!(err.contains("bogons.rpol"), "names the leaf module: {err}");
}

#[test]
fn rpol_default_graph_budget_fits_a_multi_mib_irr_scale_unit() {
    // A single ~9 MiB unit — over the pre-configurable 8 MiB budget —
    // loads under the default (IRR-scale renders are single files well
    // past 8 MiB).
    let padding = format!("# padding\n{}\n", "#".repeat(9 * 1024 * 1024));
    let source = format!("{RPOL_BUDGET_POLICY}{padding}");
    let dir = rpol_budget_config_dir(&source, "");
    let config = load_dir(&dir).expect("multi-MiB rpol unit loads under the default budget");
    assert_eq!(
        config.policy.rpol_max_graph_bytes,
        rustbgpd_policy::rpol::DEFAULT_MAX_GRAPH_BYTES
    );
}

#[test]
fn rpol_unit_over_the_configured_graph_budget_is_rejected() {
    // ~1.5 MiB unit against the 1 MiB floor: same diagnostic shape as
    // the pre-configurable budget.
    let padding = format!("# padding\n{}\n", "#".repeat(1536 * 1024));
    let source = format!("{RPOL_BUDGET_POLICY}{padding}");
    let dir = rpol_budget_config_dir(&source, "rpol_max_graph_bytes = 1048576");
    let err = load_dir(&dir).expect_err("unit over the configured budget rejects the load");
    assert!(
        err.contains("resolved module graph exceeds 1048576 total source bytes"),
        "{err}"
    );
}

#[test]
fn rpol_max_graph_bytes_out_of_range_is_a_load_error() {
    for budget in ["1024", "17179869185"] {
        let dir = rpol_budget_config_dir(
            RPOL_BUDGET_POLICY,
            &format!("rpol_max_graph_bytes = {budget}"),
        );
        let err = load_dir(&dir).expect_err("out-of-range budget rejects the load");
        assert!(
            err.contains("rpol_max_graph_bytes") && err.contains("out of range"),
            "{err}"
        );
    }
}

/// Direction legality is enforced when the chain is attached: a
/// `prepend as peer` member is import-only, and binding it as an
/// export chain fails the config load with the exact diagnostic.
#[test]
fn prepend_as_peer_rejected_on_export_attachment() {
    let dir = rpol_directional_config_dir(PREPEND_OPERANDS_RPOL, r#""peer-pad""#, r#""peer-pad""#);
    let error = load_dir(&dir).expect_err("export-bound `prepend as peer` must fail the load");
    assert!(error.contains("peer-pad"), "{error}");
    assert!(error.contains("inbound-pad"), "{error}");
    assert!(error.contains("prepend as peer"), "{error}");
    assert!(error.contains("import-only"), "{error}");
    assert!(error.contains("own-AS loop"), "{error}");
}

/// The legal cells of the matrix: `peer` on import, `self`/`origin` on
/// export (and import). The export chain's rpol members carry the
/// attach-time `[global] asn`, so `prepend as self` resolves to it.
#[test]
fn prepend_operand_legal_directions_attach_and_resolve() {
    let dir = rpol_directional_config_dir(
        PREPEND_OPERANDS_RPOL,
        r#""peer-pad", "origin-pad""#,
        r#""self-pad", "origin-pad""#,
    );
    let config = load_dir(&dir).expect("legal operand placements load");
    let neighbor = &config.neighbors[0];
    let (import, export) = config
        .effective_policy_chains_for_neighbor(neighbor)
        .expect("chains resolve");
    let import = import.expect("import chain configured");
    let export = export.expect("export chain configured");

    // Attach-time local_asn stamp on every rpol member.
    for chain in [&import, &export] {
        for member in &chain.policies {
            let compiled = member.rpol.as_deref().expect("rpol member");
            assert_eq!(compiled.local_asn, Some(65001));
        }
    }

    let ctx = rustbgpd_policy::RouteContext {
        prefix: Some(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            "10.10.3.0".parse().unwrap(),
            24,
        ))),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 1,
        origin_asn: Some(64500),
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: Some(65002),
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    // Import: `prepend as peer` resolves to the neighbor's ASN (the
    // later `origin-pad` member wins the shared prepend slot — chain
    // merge semantics — so evaluate the peer-pad member's chain alone).
    let peer_only = rustbgpd_policy::PolicyChain::from_named(vec![import.policies[0].clone()]);
    let result = peer_only.evaluate(&ctx);
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Permit);
    assert_eq!(result.modifications.as_path_prepend, Some((65002, 3)));

    // Export: `prepend as self` resolves to the daemon's [global] asn.
    let self_only = rustbgpd_policy::PolicyChain::from_named(vec![export.policies[0].clone()]);
    let result = self_only.evaluate(&ctx);
    assert_eq!(result.modifications.as_path_prepend, Some((65001, 3)));

    // Both directions: `origin` resolves from the route.
    let result = export.evaluate(&ctx);
    assert_eq!(result.modifications.as_path_prepend, Some((64500, 2)));
}

/// `prepend as peer` on the GLOBAL export chain is rejected too — the
/// direction check lives in the shared resolver, not per-neighbor.
#[test]
fn prepend_as_peer_rejected_on_global_export_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("policies")).expect("mkdir");
    fs::write(dir.path().join("policies/core.rpol"), PREPEND_OPERANDS_RPOL).expect("write rpol");
    let toml = tier_authorized_uds_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = ["policies/core.rpol"]
export_chain = ["peer-pad"]
"#,
    );
    fs::write(dir.path().join("config.toml"), toml).expect("write config");
    let error = load_dir(&dir).expect_err("global export `prepend as peer` must fail");
    assert!(error.contains("prepend as peer"), "{error}");
    assert!(error.contains("import-only"), "{error}");
}

#[test]
fn rpol_compile_diagnostics_fail_config_load() {
    let dir = rpol_config_dir(
        "policy broken { term t { if route.nosuch == 1 { reject } } }",
        r#""broken""#,
    );
    let error = load_dir(&dir).expect_err("bad rpol file must fail the load");
    assert!(error.contains("core.rpol"), "{error}");
    // The ariadne-rendered diagnostic is embedded in the error string.
    assert!(
        error.contains("route.nosuch") || error.contains("nosuch"),
        "{error}"
    );
}

#[test]
fn rpol_missing_file_fails_config_load() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""bogon-filter""#);
    fs::remove_file(dir.path().join("policies/core.rpol")).unwrap();
    let error = load_dir(&dir).expect_err("missing rpol file must fail the load");
    assert!(error.contains("failed to read"), "{error}");
}

/// LAN-218: entries are `canonicalize()`d before reading, so an
/// `rpol_files` path that points through a symlink still resolves to and
/// loads the real file's content.
#[cfg(unix)]
#[test]
fn rpol_symlinked_file_canonicalizes_and_loads() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""bogon-filter""#);
    std::os::unix::fs::symlink(
        dir.path().join("policies/core.rpol"),
        dir.path().join("policies/link.rpol"),
    )
    .unwrap();
    let toml_path = dir.path().join("config.toml");
    let toml = fs::read_to_string(&toml_path).unwrap().replace(
        r#"rpol_files = ["policies/core.rpol"]"#,
        r#"rpol_files = ["policies/link.rpol"]"#,
    );
    fs::write(&toml_path, toml).unwrap();

    let config = load_dir(&dir).expect("symlinked rpol file loads");
    // Content read through the symlink: both policies registered.
    assert_eq!(config.policy.rpol.policies.len(), 2);
    assert!(config.policy.rpol.policies.contains_key("bogon-filter"));
    assert!(config.policy.rpol.policies.contains_key("customer-in"));
}

#[test]
fn rpol_name_collision_with_toml_definition_fails() {
    let dir = rpol_config_dir("policy toml-pass { term t { reject } }", r#""toml-pass""#);
    let error = load_dir(&dir).expect_err("collision must fail the load");
    assert!(error.contains("toml-pass"), "{error}");
    assert!(error.contains("policy.definitions"), "{error}");
}

#[test]
fn rpol_name_collision_across_files_fails() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""bogon-filter""#);
    fs::write(
        dir.path().join("policies/dup.rpol"),
        "policy bogon-filter { term t { reject } }",
    )
    .unwrap();
    let toml_path = dir.path().join("config.toml");
    let toml = fs::read_to_string(&toml_path).unwrap().replace(
        r#"rpol_files = ["policies/core.rpol"]"#,
        r#"rpol_files = ["policies/core.rpol", "policies/dup.rpol"]"#,
    );
    fs::write(&toml_path, toml).unwrap();
    let error = load_dir(&dir).expect_err("cross-file collision must fail the load");
    assert!(error.contains("bogon-filter"), "{error}");
    assert!(error.contains("already defined"), "{error}");
}

#[test]
fn rpol_chain_reference_arity_and_argument_errors() {
    // Missing required argument.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""customer-in""#))
        .expect_err("arity error must fail the load");
    assert!(error.contains("takes 1 parameter(s), 0 given"), "{error}");
    // Extra argument on a zero-param policy.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""bogon-filter(1)""#))
        .expect_err("arity error must fail the load");
    assert!(error.contains("takes 0 parameter(s), 1 given"), "{error}");
    // Non-u32 argument.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""customer-in(high)""#))
        .expect_err("argument type error must fail the load");
    assert!(error.contains("is not a u32"), "{error}");
    // Unknown policy.
    let error = load_dir(&rpol_config_dir(RPOL_SOURCE, r#""nope(1)""#))
        .expect_err("unknown policy must fail the load");
    assert!(error.contains("undefined policy"), "{error}");
}

/// ADR-0076 planner classification: an edited `.rpol` file whose
/// compiled content differs is a `policy_chain` impact for exactly the
/// peers referencing it; reloading unchanged content is a no-op.
#[test]
fn rpol_edit_classifies_policy_chain_impact_for_referencing_peers_only() {
    let dir = rpol_config_dir(RPOL_SOURCE, r#""customer-in(200)""#);
    let old = load_dir(&dir).expect("initial load");

    // Same content reloaded → no diff at all.
    let same = load_dir(&dir).expect("reload");
    let diff = diff_config(&old, &same);
    assert!(!diff.policy.rpol_changed);
    assert!(!diff.has_any_changes(), "{diff:?}");

    // Edited file, materially different compiled content.
    fs::write(
        dir.path().join("policies/core.rpol"),
        RPOL_SOURCE.replace("ge 24 le 28", "ge 24 le 32"),
    )
    .unwrap();
    let new = load_dir(&dir).expect("reload after edit");
    let diff = diff_config(&old, &new);
    assert!(diff.policy.rpol_changed);
    assert!(diff.has_reload_applied_changes());
    // Exactly the referencing neighbor is impacted, as a pure
    // policy-chain move (live-impact executor eligible).
    assert_eq!(diff.effective_neighbor_impact.len(), 1);
    let impact = &diff.effective_neighbor_impact[0];
    assert_eq!(impact.address, "192.0.2.1");
    assert!(impact.kind.is_policy_chain());
    assert!(
        impact
            .reasons
            .iter()
            .any(|r| r == "rpol policy file changed"),
        "{:?}",
        impact.reasons
    );
    // v1 transactions cannot stage .rpol content — fail closed.
    let class = classify_config_transaction_v1(&diff);
    assert!(
        class
            .unsupported_sections
            .iter()
            .any(|s| s.contains("rpol_files")),
        "{class:?}"
    );

    // Comment-only edits compile to identical content → the resolved
    // chains compare equal, but the source-level registry diff still
    // reports the file as changed (refresh is idempotent).
    fs::write(
        dir.path().join("policies/core.rpol"),
        format!("# comment\n{RPOL_SOURCE}"),
    )
    .unwrap();
    let commented = load_dir(&dir).expect("reload after comment edit");
    let diff = diff_config(&old, &commented);
    assert!(diff.policy.rpol_changed);
    // No resolved chain moved, so no per-neighbor impact.
    assert!(diff.effective_neighbor_impact.is_empty(), "{diff:?}");
}
