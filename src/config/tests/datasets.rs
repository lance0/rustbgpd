use super::*;

/// Initial load: declaration + `[policy.datasets]` binding + file →
/// a generation-1 handle, chains resolve and probe it.
#[test]
fn dataset_binds_at_load_and_chains_probe_it() {
    let dir = dataset_config_dir("# customers\n64500\n");
    let config = load_dir(&dir).expect("config with a dataset loads");
    let handle = config
        .policy
        .dataset_bindings
        .get("customers")
        .expect("bound");
    assert_eq!(handle.pin().generation, 1);
    assert!(config.policy.dataset_events.swapped.is_empty());

    let (import, _) = config
        .effective_policy_chains_for_neighbor(&config.neighbors[0])
        .expect("chains resolve");
    let import = import.expect("import chain configured");
    assert!(import.references_dataset("customers"));
    assert_eq!(
        import.evaluate(&origin_ctx(64500)).action,
        rustbgpd_policy::PolicyAction::Permit
    );
    assert_eq!(
        import.evaluate(&origin_ctx(64999)).action,
        rustbgpd_policy::PolicyAction::Deny
    );
}

/// Both directions of declaration ↔ binding coverage, and an
/// unreadable file at initial load, are load errors.
#[test]
fn dataset_binding_validation_rejects_mismatches() {
    // Declared but no [policy.datasets] entry.
    let dir = dataset_config_dir("64500\n");
    let toml = fs::read_to_string(dir.path().join("config.toml")).unwrap();
    fs::write(
        dir.path().join("config.toml"),
        toml.replace(
            "[policy.datasets.customers]\npath = \"datasets/customers.list\"\n",
            "",
        ),
    )
    .unwrap();
    let err = load_dir(&dir).expect_err("missing binding entry");
    assert!(
        err.contains("has no [policy.datasets.customers] entry"),
        "{err}"
    );

    // Entry without a declaration.
    let dir = dataset_config_dir("64500\n");
    let toml = fs::read_to_string(dir.path().join("config.toml")).unwrap();
    fs::write(
        dir.path().join("config.toml"),
        toml.replace(
            "[policy.datasets.customers]\npath = \"datasets/customers.list\"",
            "[policy.datasets.customers]\npath = \"datasets/customers.list\"\n\n\
             [policy.datasets.orphan]\npath = \"datasets/customers.list\"",
        ),
    )
    .unwrap();
    let err = load_dir(&dir).expect_err("orphan binding entry");
    assert!(
        err.contains("does not match any `dataset` declaration"),
        "{err}"
    );

    // Initial load with an unparseable file: hard error (no prior
    // snapshot exists to keep).
    let dir = dataset_config_dir("not-an-asn\n");
    let err = load_dir(&dir).expect_err("bad file at initial load");
    assert!(err.contains("line 1"), "{err}");
}

/// The SIGHUP shape (`load_with_diagnostics_and_datasets`): declared
/// datasets reuse the running handles — changed content swaps in
/// place (generation bump + `dataset_events.swapped`), content-equal
/// re-reads are no-ops, and a bad file keeps the prior snapshot with
/// the error recorded instead of rejecting the reload. Chain identity
/// is untouched throughout (the #775 content-equal reinstall skip
/// sees no change).
#[test]
fn dataset_reload_reuses_handles_swaps_scoped_and_keeps_prior_on_failure() {
    let dir = dataset_config_dir("64500\n");
    let path = dir.path().join("config.toml");
    let path = path.to_str().unwrap();
    let initial = Config::load_with_diagnostics(path).expect("initial load");
    let handle = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
    let (chain_before, _) = initial
        .effective_policy_chains_for_neighbor(&initial.neighbors[0])
        .expect("chains resolve");

    // Content change: same handle, generation bump, swapped recorded.
    fs::write(dir.path().join("datasets/customers.list"), "64500\n64999\n").unwrap();
    let reloaded =
        Config::load_with_diagnostics_and_datasets(path, Some(&initial.policy.dataset_bindings))
            .expect("reload with changed dataset");
    assert!(std::sync::Arc::ptr_eq(
        &handle,
        reloaded.policy.dataset_bindings.get("customers").unwrap()
    ));
    assert_eq!(handle.pin().generation, 2);
    assert_eq!(reloaded.policy.dataset_events.swapped, vec!["customers"]);
    assert!(reloaded.policy.dataset_events.failed.is_empty());
    // The chain installed from the OLD config now permits the new
    // member — the swap reached it without any reinstall — and the
    // re-resolved chain is content-equal (no Route Refresh storm).
    let chain_before = chain_before.expect("import chain");
    assert_eq!(
        chain_before.evaluate(&origin_ctx(64999)).action,
        rustbgpd_policy::PolicyAction::Permit
    );
    let (chain_after, _) = reloaded
        .effective_policy_chains_for_neighbor(&reloaded.neighbors[0])
        .expect("chains resolve");
    assert_eq!(Some(&chain_before), chain_after.as_ref());

    // Content-equal re-read (reordered + comments): no swap, no event.
    fs::write(
        dir.path().join("datasets/customers.list"),
        "# reordered\n64999\n64500\n",
    )
    .unwrap();
    let unchanged =
        Config::load_with_diagnostics_and_datasets(path, Some(&reloaded.policy.dataset_bindings))
            .expect("content-equal reload");
    assert_eq!(handle.pin().generation, 2);
    assert!(unchanged.policy.dataset_events.swapped.is_empty());

    // Bad file: reload still succeeds, prior snapshot retained, error
    // surfaced on the handle and in the events.
    fs::write(
        dir.path().join("datasets/customers.list"),
        "garbage entry\n",
    )
    .unwrap();
    let failed =
        Config::load_with_diagnostics_and_datasets(path, Some(&unchanged.policy.dataset_bindings))
            .expect("reload survives a bad dataset file");
    assert_eq!(handle.pin().generation, 2, "prior snapshot retained");
    assert_eq!(failed.policy.dataset_events.failed.len(), 1);
    assert_eq!(failed.policy.dataset_events.failed[0].0, "customers");
    let status = handle.status();
    assert!(status.last_error.is_some(), "{status:?}");
    assert_eq!(
        failed
            .policy
            .dataset_bindings
            .get("customers")
            .unwrap()
            .pin()
            .data
            .records(),
        2,
        "old data still probing"
    );
}

#[test]
fn staged_dataset_reload_defers_live_handle_mutation_until_commit() {
    let dir = dataset_config_dir("64500\n");
    let path = dir.path().join("config.toml");
    let path = path.to_str().unwrap();
    let initial = Config::load_with_diagnostics(path).expect("initial load");
    let live = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());

    fs::write(dir.path().join("datasets/customers.list"), "64500\n64999\n").unwrap();
    let mut staged =
        Config::load_with_diagnostics_and_staged_datasets(path, &initial.policy.dataset_bindings)
            .expect("stage changed dataset");

    assert_eq!(live.pin().generation, 1);
    assert_eq!(live.pin().data.records(), 1);
    assert_eq!(staged.policy.dataset_events.swapped, vec!["customers"]);
    assert!(!std::sync::Arc::ptr_eq(
        &live,
        staged.policy.dataset_bindings.get("customers").unwrap()
    ));

    let commit = staged.prepare_staged_datasets(&initial.policy.dataset_bindings);
    assert!(std::sync::Arc::ptr_eq(
        &live,
        staged.policy.dataset_bindings.get("customers").unwrap()
    ));
    assert_eq!(live.pin().generation, 1);
    commit.commit();
    assert_eq!(live.pin().generation, 2);
    assert_eq!(live.pin().data.records(), 2);

    fs::write(
        dir.path().join("datasets/customers.list"),
        "garbage entry\n",
    )
    .unwrap();
    let mut failed =
        Config::load_with_diagnostics_and_staged_datasets(path, &staged.policy.dataset_bindings)
            .expect("stage failed refresh against prior snapshot");
    assert_eq!(failed.policy.dataset_events.failed.len(), 1);
    assert!(live.status().last_error.is_none());
    assert_eq!(live.pin().generation, 2);

    let commit = failed.prepare_staged_datasets(&staged.policy.dataset_bindings);
    assert!(live.status().last_error.is_none());
    commit.commit();
    assert!(live.status().last_error.is_some());
    assert_eq!(live.pin().generation, 2);
    assert_eq!(live.pin().data.records(), 2);
}

#[test]
fn dataset_generation_restores_content_and_error_through_stable_handle() {
    let dir = dataset_config_dir("64500\n");
    let path = dir.path().join("config.toml");
    let path = path.to_str().unwrap();
    let initial = Config::load_with_diagnostics(path).unwrap();
    let live = Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
    live.record_error("prior source unavailable");
    let prior = live.pin();
    fs::write(dir.path().join("datasets/customers.list"), "64999\n").unwrap();
    let mut candidate =
        Config::load_with_diagnostics_and_staged_datasets(path, &initial.policy.dataset_bindings)
            .unwrap();
    let staged = candidate.prepare_staged_datasets(&initial.policy.dataset_bindings);
    let prepared = staged.prepare_generation(&initial, &candidate).unwrap();
    assert_eq!(prepared.changed_names(), ["customers"]);
    assert!(Arc::ptr_eq(&prior, &live.pin()));
    let rollback = prepared.publish();
    assert_eq!(live.pin().generation, 2);
    assert_ne!(live.pin().data, prior.data);
    assert!(live.status().last_error.is_none());
    // Compensation must use the retained data, not the now-overwritten file.
    fs::write(dir.path().join("datasets/customers.list"), "invalid\n").unwrap();
    rollback.restore();
    assert_eq!(live.pin().generation, 3);
    assert_eq!(live.pin().data, prior.data);
    assert_eq!(
        live.status().last_error.as_deref(),
        Some("prior source unavailable")
    );
    assert!(Arc::ptr_eq(
        &live,
        candidate.policy.dataset_bindings.get("customers").unwrap()
    ));
    assert_eq!(Arc::strong_count(&prior), 1, "rollback pin released");
}

#[test]
fn dataset_generation_equal_content_restores_error_without_advancing() {
    let dir = dataset_config_dir("64500\n");
    let path = dir.path().join("config.toml");
    let path = path.to_str().unwrap();
    let initial = Config::load_with_diagnostics(path).unwrap();
    let live = Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
    live.record_error("prior error");
    let prior = live.pin();
    let mut candidate =
        Config::load_with_diagnostics_and_staged_datasets(path, &initial.policy.dataset_bindings)
            .unwrap();
    let staged = candidate.prepare_staged_datasets(&initial.policy.dataset_bindings);
    let prepared = staged.prepare_generation(&initial, &candidate).unwrap();
    assert!(prepared.changed_names().is_empty());
    let rollback = prepared.publish();
    assert!(live.status().last_error.is_none());
    assert!(Arc::ptr_eq(&prior, &live.pin()));
    rollback.restore();
    assert_eq!(live.status().last_error.as_deref(), Some("prior error"));
    assert!(Arc::ptr_eq(&prior, &live.pin()));
    assert_eq!(live.pin().generation, 1);
}

#[test]
fn dataset_generation_rejects_invalid_batch_without_publishing_first_input() {
    let dir = dataset_config_dir("64500\n");
    let config_path = dir.path().join("config.toml");
    let policy_path = dir.path().join("policies/core.rpol");
    let config = fs::read_to_string(&config_path).unwrap();
    fs::write(
        &config_path,
        format!("{config}\n[policy.datasets.suppliers]\npath = \"datasets/suppliers.list\"\n"),
    )
    .unwrap();
    let policy = fs::read_to_string(&policy_path).unwrap();
    fs::write(&policy_path, format!("dataset asn-set suppliers\n{policy}")).unwrap();
    fs::write(dir.path().join("datasets/suppliers.list"), "64501\n").unwrap();
    let initial = Config::load_with_diagnostics(config_path.to_str().unwrap()).unwrap();
    fs::write(dir.path().join("datasets/customers.list"), "64999\n").unwrap();
    fs::write(dir.path().join("datasets/suppliers.list"), "invalid\n").unwrap();
    let mut candidate = Config::load_with_diagnostics_and_staged_datasets(
        config_path.to_str().unwrap(),
        &initial.policy.dataset_bindings,
    )
    .unwrap();
    let staged = candidate.prepare_staged_datasets(&initial.policy.dataset_bindings);
    assert!(staged.prepare_generation(&initial, &candidate).is_err());
    for handle in initial.policy.dataset_bindings.handles() {
        assert_eq!(handle.pin().generation, 1);
        assert!(handle.status().last_error.is_none());
    }
}

#[test]
fn dataset_generation_rejects_changed_mapping_or_handle_identity() {
    let dir = dataset_config_dir("64500\n");
    let initial = load_dir(&dir).unwrap();
    let mut candidate = initial.clone();
    candidate
        .policy
        .datasets
        .get_mut("customers")
        .unwrap()
        .path
        .push_str(".next");
    assert!(
        StagedDatasetCommit {
            updates: Vec::new()
        }
        .prepare_generation(&initial, &candidate)
        .is_err()
    );
    candidate = initial.clone();
    candidate.policy.dataset_bindings = initial.policy.dataset_bindings.detached_clone();
    assert!(
        StagedDatasetCommit {
            updates: Vec::new()
        }
        .prepare_generation(&initial, &candidate)
        .is_err()
    );
}

#[test]
fn dataset_generation_headroom_reserves_forward_and_compensation() {
    use rustbgpd_policy::datasets::{DatasetData, DatasetHandle, DatasetKind, DatasetSnapshot};
    use rustbgpd_policy::sets::AsnSet;
    let data = DatasetData::Asn(AsnSet::new([64500]));
    let handle = Arc::new(DatasetHandle::new(
        "customers",
        DatasetKind::Asn,
        data.clone(),
    ));
    for (generation, changed, accepted) in [
        (u64::MAX - 2, true, true),
        (u64::MAX - 1, true, false),
        (u64::MAX, true, false),
        (u64::MAX, false, true),
    ] {
        let prior = DatasetPrior {
            handle: Arc::clone(&handle),
            snapshot: Arc::new(DatasetSnapshot {
                generation,
                data: data.clone(),
            }),
            error: None,
            content_changed: changed,
        };
        assert_eq!(prior.validate_generation_headroom().is_ok(), accepted);
    }
}

#[test]
fn dataset_path_change_is_visible_and_transaction_unsupported() {
    let dir = dataset_config_dir("64500\n");
    let current = load_dir(&dir).expect("config with dataset input loads");
    let mut candidate = current.clone();
    candidate
        .policy
        .datasets
        .get_mut("customers")
        .expect("binding")
        .path
        .push_str(".next");

    let diff = diff_config(&current, &candidate);
    let class = classify_config_transaction_v1(&diff);

    assert!(diff.policy.datasets_changed);
    assert!(diff.has_reload_applied_changes());
    assert_eq!(
        config_diff_json_value(&diff)["reload_applied"]["datasets_changed"],
        true
    );
    let text = format_config_diff(&diff);
    assert!(text.contains("policy dataset bindings / paths"), "{text}");
    assert_eq!(
        class.unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );
    assert!(!class.is_committable());

    let mut fib_current = current;
    fib_current.fib_tables.push(FibTableConfig {
        name: "edge".to_string(),
        table_id: 1000,
        metric: 200,
        families: vec!["ipv4_unicast".to_string()],
        allowed_peer_groups: Vec::new(),
        allowed_neighbors: Vec::new(),
        max_routes: None,
        maximum_paths: None,
        maximum_paths_ebgp: None,
        maximum_paths_ibgp: None,
    });
    let mut mixed_candidate = fib_current.clone();
    mixed_candidate.fib_tables[0].metric = 201;
    mixed_candidate
        .policy
        .datasets
        .get_mut("customers")
        .expect("binding")
        .path
        .push_str(".next");
    let mixed = classify_config_transaction_v1(&diff_config(&fib_current, &mixed_candidate));
    assert_eq!(mixed.supported_sections, vec!["[[fib_tables]]"]);
    assert_eq!(
        mixed.unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );
    assert!(!mixed.is_committable());
}

#[test]
fn full_snapshot_transaction_with_dataset_inputs_is_rejected_without_handle_mutation() {
    let dir = dataset_config_dir("64500\n");
    let current = load_dir(&dir).expect("config with dataset input loads");
    let live = std::sync::Arc::clone(
        current
            .policy
            .dataset_bindings
            .get("customers")
            .expect("live binding"),
    );
    let generation = live.pin().generation;
    let mut candidate = load_dir(&dir).expect("candidate independently reloads dataset input");
    let candidate_binding = std::sync::Arc::clone(
        candidate
            .policy
            .dataset_bindings
            .get("customers")
            .expect("candidate binding"),
    );
    candidate.neighbors[0].description = Some("changed by transaction".to_string());

    let diff = diff_config(&current, &candidate);
    let class = classify_config_transaction_v1(&diff);

    assert!(!diff.policy.datasets_changed, "binding is unchanged");
    assert_eq!(class.supported_sections, vec!["[[neighbors]] modify"]);
    assert_eq!(
        class.unsupported_sections,
        vec![TRANSACTION_EXTERNAL_POLICY_INPUTS_SECTION]
    );
    assert!(!class.is_committable());
    assert!(!std::sync::Arc::ptr_eq(&live, &candidate_binding));
    assert_eq!(live.pin().generation, generation);
}

#[test]
fn only_fib_transactions_avoid_full_candidate_snapshot_staging() {
    assert!(!transaction_stages_full_candidate_snapshot(&[
        TRANSACTION_FIB_SECTION.to_string(),
    ]));

    for section in [
        TRANSACTION_DYNAMIC_SECTION,
        TRANSACTION_NEIGHBOR_ADD_SECTION,
        TRANSACTION_NEIGHBOR_DELETE_SECTION,
        TRANSACTION_NEIGHBOR_MODIFY_SECTION,
        TRANSACTION_PEER_GROUP_CATALOG_SECTION,
        TRANSACTION_POLICY_DEFINITIONS_SECTION,
        TRANSACTION_POLICY_NEIGHBOR_SETS_SECTION,
        TRANSACTION_POLICY_GLOBAL_CHAINS_SECTION,
        TRANSACTION_POLICY_LIVE_IMPACT_SECTION,
        TRANSACTION_SESSION_RESHAPE_SECTION,
    ] {
        assert!(
            transaction_stages_full_candidate_snapshot(&[section.to_string()]),
            "{section} must stay behind the external-input fence"
        );
    }
}
