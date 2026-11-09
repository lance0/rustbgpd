use std::collections::{HashMap, HashSet};

use rustbgpd_api::peer_types::{
    FibTableSnapshot, PeerKey, PeerLifecycleError, PeerManagerNeighborConfig,
    PeerReconcileAuthority, PeerReconcileEffect, PeerReconcileOutcome, ReconcileFailure,
    ReconcileFailureKind, RuntimeConfigDiff, RuntimeConfigDiffError, RuntimeConfigTransactionPlan,
    RuntimeConfigTransactionPlanError, RuntimeConfigTransactionStatus,
};
use tracing::{info, warn};

use crate::config::Config;
use crate::policy_admin::fib_table_snapshot_to_config;

use super::PeerManager;

/// Load a `DiffRuntimeConfig` / `PlanConfigTransaction` candidate. This
/// reads the candidate's external policy sources, so the actor runs it on
/// the blocking pool (see `PeerManager::spawn_candidate_load`).
///
/// Only the config-transaction path captures the candidate's external
/// sources for identity verification (ADR-0130). The gNMI Set bridge plans
/// without capture, so its candidates classify as `Unverified` and keep the
/// #1370 presence fence.
///
/// `limits` confines the candidate's external sources (callers below
/// `operator_only`); `None` is for operator callers.
pub(super) fn load_runtime_candidate(
    candidate_toml: &str,
    capture_external_inputs: bool,
    limits: Option<&crate::config::CandidateSourceLimits>,
) -> Result<Config, crate::config::CandidateLoadError> {
    #[cfg(test)]
    load_latch::hold_if_marked(candidate_toml);
    Config::load_rpc_candidate(
        candidate_toml,
        "candidate runtime config",
        capture_external_inputs,
        limits,
    )
}

impl PeerManager {
    /// Reconcile the peer set as one operation: one import-roster
    /// publication however many peers it adds, removes or replaces.
    pub(super) async fn reconcile_peers(
        &mut self,
        added: Vec<PeerManagerNeighborConfig>,
        removed: Vec<PeerKey>,
        changed: Vec<PeerManagerNeighborConfig>,
    ) -> PeerReconcileOutcome {
        let batch = self.peers.begin_batch();
        let result = Box::pin(self.reconcile_peers_unbatched(added, removed, changed)).await;
        self.peers.end_batch(batch);
        result
    }

    #[expect(
        clippy::too_many_lines,
        reason = "peer reconciliation keeps remove, purge-aware replacement, runtime-state replay, add, and typed outcome accounting in one ordered pass"
    )]
    async fn reconcile_peers_unbatched(
        &mut self,
        added: Vec<PeerManagerNeighborConfig>,
        removed: Vec<PeerKey>,
        changed: Vec<PeerManagerNeighborConfig>,
    ) -> PeerReconcileOutcome {
        let mut effects = Vec::new();
        let mut failures = Vec::new();
        let mut authority = PeerReconcileAuthority::Known;
        let added_count = added.len();
        let removed_count = removed.len();
        let changed_count = changed.len();

        // Capture per-peer operator-runtime state that should survive a
        // delete-then-readd cycle. Runtime state is not encoded in the TOML
        // candidate, so SIGHUP reconcile must carry it across explicitly.
        // A changed config `admin_down` overrides the carried admin state.
        // Taking a peer down sends the configured reason on the teardown.
        let mut stop_reasons = HashMap::new();
        let preserved_runtime_state: HashMap<PeerKey, (bool, bool)> = changed
            .iter()
            .filter_map(|cfg| {
                let peer = PeerKey::new(cfg.address, cfg.interface.clone());
                self.peers.get(&peer).map(|managed| {
                    let enabled = super::lifecycle::config_admin_enable(managed, cfg)
                        .unwrap_or(managed.enabled);
                    if let Some(reason) =
                        super::lifecycle::replacement_stop_reason(managed.enabled, enabled, cfg)
                    {
                        stop_reasons.insert(peer.clone(), reason);
                    }
                    (peer, (enabled, managed.advertise_graceful_shutdown))
                })
            })
            .collect();

        // Detach removed peers, and changed peers for delete-then-re-add,
        // then stop their sessions together (`bounded_fan_out`): sessions
        // that stopped draining commands cost one delete window per 64 of
        // them, not one per peer. Each changed peer is re-added only after
        // its old sessions are gone.
        let mut detached = Vec::with_capacity(removed.len() + changed.len());
        for addr in &removed {
            match self
                .detach_peer_for_delete(addr.clone(), false, None, true, None, None)
                .await
            {
                Ok(peer) => detached.push(peer),
                Err(e) => {
                    warn!(peer = %addr, error = %e, "reconcile: failed to remove peer");
                    failures.push(ReconcileFailure {
                        kind: ReconcileFailureKind::Remove,
                        peer: addr.clone(),
                        error: e.to_string(),
                    });
                    continue;
                }
            }
            effects.push(PeerReconcileEffect::Removed(addr.clone()));
        }
        // A changed peer whose discard list changes is purge-reset first;
        // every such purge is sent at once.
        let mut prepared = Vec::with_capacity(changed.len());
        let mut remove_failures = Vec::new();
        for cfg in &changed {
            let addr = PeerKey::new(cfg.address, cfg.interface.clone());
            match self
                .prepare_delete(
                    addr.clone(),
                    false,
                    cfg.tcp_ao.as_ref(),
                    Some(&cfg.discard_path_attributes),
                )
                .await
            {
                Ok(delete) => prepared.push((cfg, delete)),
                Err(e) => remove_failures.push((addr, e)),
            }
        }
        let purging: Vec<PeerKey> = prepared
            .iter()
            .filter(|(_, delete)| delete.purge_reset)
            .map(|(_, delete)| delete.peer().clone())
            .collect();
        let purge = self.purge_reset_for_delete(&purging).await;
        let mut purged: HashMap<PeerKey, Result<(), PeerLifecycleError>> =
            purging.iter().cloned().zip(purge.results).collect();
        let mut replaced = Vec::with_capacity(changed.len());
        for (cfg, delete) in prepared {
            let addr = delete.peer().clone();
            if let Some(Err(e)) = purged.remove(&addr) {
                remove_failures.push((addr, e));
                continue;
            }
            match self.detach_prepared(delete, false, stop_reasons.remove(&addr)) {
                Ok(peer) => {
                    detached.push(peer);
                    replaced.push(cfg);
                }
                Err(e) => remove_failures.push((addr, e)),
            }
        }
        // Every purged peer is detached now, so retiring the failed peers'
        // candidates cannot mistake a purged peer's BackToIdle for a live
        // session failure.
        self.retire_purged_candidates(purge.retiring).await;
        for (addr, e) in remove_failures {
            warn!(peer = %addr, error = %e, "reconcile: failed to remove changed peer");
            failures.push(ReconcileFailure {
                kind: ReconcileFailureKind::ChangeRemove,
                peer: addr,
                error: e.to_string(),
            });
        }
        self.delete_detached_peers(detached).await;
        // Changed peers: re-add
        for cfg in replaced {
            let addr = PeerKey::new(cfg.address, cfg.interface.clone());
            let was_enabled = preserved_runtime_state
                .get(&addr)
                .is_none_or(|(enabled, _)| *enabled);
            if let Err(e) = self
                .add_peer_with_admin_state(cfg.clone(), false, was_enabled)
                .await
            {
                warn!(peer = %addr, error = %e, "reconcile: failed to re-add changed peer");
                failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeAdd,
                    peer: addr.clone(),
                    error: e.to_string(),
                });
                effects.push(PeerReconcileEffect::RemovedForFailedReplacement(
                    addr.clone(),
                ));
                self.reap_deleted_peer_metric_series_for_key(&addr);
            } else {
                effects.push(PeerReconcileEffect::Replaced(addr));
            }
        }
        // Replay preserved RFC 8326 toggles onto the freshly added peers. This
        // goes through the same path as the operator's `rbgp gshut` so
        // the live session bool, ManagedPeer desired state, and RIB refresh all
        // advance in lockstep. Disabled state was already applied during
        // add_peer_with_admin_state above, so a disabled changed peer never
        // transiently starts before being disabled again.
        for (addr, (_was_enabled, gshut_enabled)) in preserved_runtime_state {
            if !gshut_enabled {
                continue;
            }
            let label = addr.to_string();
            if let Err(e) = self.set_graceful_shutdown(Some(addr), true).await {
                warn!(
                    peer = %label,
                    error = %e,
                    "reconcile: failed to replay graceful-shutdown toggle on changed peer"
                );
                authority = PeerReconcileAuthority::Diverged;
            }
        }
        // Add new peers
        for cfg in added {
            let addr = PeerKey::new(cfg.address, cfg.interface.clone());
            if let Err(e) = self.add_peer(cfg, false).await {
                warn!(peer = %addr, error = %e, "reconcile: failed to add new peer");
                failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Add,
                    peer: addr,
                    error: e.to_string(),
                });
            } else {
                effects.push(PeerReconcileEffect::Added(addr));
            }
        }
        info!(
            added = added_count,
            removed = removed_count,
            changed = changed_count,
            failures = failures.len(),
            "peer reconciliation complete"
        );
        PeerReconcileOutcome {
            effects,
            failures,
            authority,
        }
    }

    #[cfg(test)]
    pub(super) fn diff_runtime_config(
        &self,
        candidate_toml: &str,
    ) -> Result<RuntimeConfigDiff, RuntimeConfigDiffError> {
        self.diff_loaded_runtime_config(&load_runtime_candidate(
            candidate_toml,
            false,
            Some(&self.candidate_source_limits()),
        ))
    }

    /// Diff a candidate loaded off the actor by [`load_runtime_candidate`].
    pub(super) fn diff_loaded_runtime_config(
        &self,
        candidate: &Result<Config, crate::config::CandidateLoadError>,
    ) -> Result<RuntimeConfigDiff, RuntimeConfigDiffError> {
        let candidate = candidate.as_ref().map_err(Clone::clone)?;
        let diff = crate::config::diff_config(&self.current_config, candidate);
        runtime_config_diff_from_config_diff(&diff, None).map_err(RuntimeConfigDiffError::Internal)
    }

    #[cfg(test)]
    pub(super) async fn plan_config_transaction(
        &mut self,
        candidate_toml: &str,
        expected_runtime_snapshot_token: Option<&str>,
        verify_external_inputs: bool,
    ) -> Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError> {
        let mut candidate = load_runtime_candidate(
            candidate_toml,
            verify_external_inputs,
            Some(&self.candidate_source_limits()),
        );
        self.plan_loaded_config_transaction(&mut candidate, expected_runtime_snapshot_token)
            .await
    }

    /// Plan a candidate loaded off the actor by [`load_runtime_candidate`].
    /// A stale snapshot token is reported ahead of a candidate load error.
    /// The candidate is borrowed so the caller can drop it off the actor.
    pub(super) async fn plan_loaded_config_transaction(
        &mut self,
        candidate: &mut Result<Config, crate::config::CandidateLoadError>,
        expected_runtime_snapshot_token: Option<&str>,
    ) -> Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError> {
        let (live_snapshot, live_snapshot_identity, runtime_snapshot_token) = self
            .config_transaction_plan_context(expected_runtime_snapshot_token)
            .await?;
        let candidate = candidate.as_mut().map_err(|error| error.clone())?;
        let external_inputs = self.verified_external_inputs(candidate);
        let materialization = crate::config::materialize_rfc8212_transaction_candidate(
            &self.current_config,
            candidate,
            external_inputs,
        );
        self.finish_config_transaction_plan(
            candidate,
            materialization.as_ref(),
            external_inputs,
            live_snapshot,
            live_snapshot_identity,
            runtime_snapshot_token,
        )
    }

    pub(super) async fn plan_preloaded_config_transaction(
        &mut self,
        candidate: &mut Config,
        expected_runtime_snapshot_token: Option<&str>,
    ) -> Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError> {
        let (live_snapshot, live_snapshot_identity, runtime_snapshot_token) = self
            .config_transaction_plan_context(expected_runtime_snapshot_token)
            .await?;
        let external_inputs = self.verified_external_inputs(candidate);
        // A retained snapshot is trusted rollback authority. Preserve every
        // non-tuple field, but carry forward an unchanged live tuple.
        let live_posture = self.current_config.rfc8212_posture();
        let candidate_posture = candidate.rfc8212_posture();
        if live_posture.config_epoch_effective == candidate_posture.config_epoch_effective
            && live_posture.policy_effective == candidate_posture.policy_effective
        {
            candidate.config_epoch = live_posture.config_epoch_raw;
            candidate.global.ebgp_requires_policy = live_posture.policy_raw;
        }
        let materialization = crate::config::materialize_rfc8212_transaction_candidate(
            &self.current_config,
            candidate,
            external_inputs,
        );
        self.finish_config_transaction_plan(
            candidate,
            materialization.as_ref(),
            external_inputs,
            live_snapshot,
            live_snapshot_identity,
            runtime_snapshot_token,
        )
    }

    /// Compare the candidate's captured external-source digest against the
    /// accepted snapshot's manifest (ADR-0130). On a byte-identical match the
    /// candidate's freshly loaded external state is verification evidence
    /// only: the running compiled `.rpol` storage and live dataset handles
    /// are re-attached in its place, so an adopted candidate cannot detach
    /// live policy state (the ADR-0121 §8 concern). Any missing digest,
    /// missing authority, or mismatch stays `Unverified` — the presence
    /// fence.
    fn verified_external_inputs(
        &self,
        candidate: &mut Config,
    ) -> crate::config::ExternalInputsIdentity {
        let Some(candidate_digest) = candidate.policy.external_sources_digest.0.take() else {
            return crate::config::ExternalInputsIdentity::Unverified;
        };
        let Some(accepted_rx) = &self.accepted_rx else {
            return crate::config::ExternalInputsIdentity::Unverified;
        };
        let accepted = accepted_rx.borrow().clone();
        if accepted.source_manifest().external_sources_sha256() != candidate_digest {
            return crate::config::ExternalInputsIdentity::Unverified;
        }
        // Re-attach the running external state. A candidate whose declared
        // roster diverges from the running config is rejected by the
        // rpol/dataset diff clauses before any executor adopts it, so a
        // rebind on such a candidate is discarded with the plan.
        candidate
            .policy
            .rpol
            .reuse_unchanged_files_from(&self.current_config.policy.rpol);
        candidate.policy.dataset_bindings = self.current_config.policy.dataset_bindings.clone();
        crate::config::ExternalInputsIdentity::VerifiedUnchanged
    }

    async fn config_transaction_plan_context(
        &mut self,
        expected_runtime_snapshot_token: Option<&str>,
    ) -> Result<
        (rustbgpd_rib::UpdateGroupSnapshot, [u8; 8], String),
        RuntimeConfigTransactionPlanError,
    > {
        // Query once and retain the exact snapshot used for both optimistic
        // concurrency and impact planning. This lets stale callers fail before
        // candidate parsing and the per-peer planning pass without introducing
        // a second RIB query or a check/use race.
        let live_snapshot = self
            .query_update_group_snapshot()
            .await
            .map_err(RuntimeConfigTransactionPlanError::Internal)?;
        let live_snapshot_identity = self.snapshot_key.digest_context(&live_snapshot);
        let runtime_snapshot_token = self
            .snapshot_key
            .token_with_context_bounded(&mut self.current_config, &live_snapshot_identity)
            .map_err(RuntimeConfigTransactionPlanError::Internal)?;
        if let Some(expected) = expected_runtime_snapshot_token.filter(|token| !token.is_empty())
            && expected != runtime_snapshot_token
        {
            return Err(RuntimeConfigTransactionPlanError::StaleSnapshot {
                expected: expected.to_string(),
                current: runtime_snapshot_token,
            });
        }
        Ok((
            live_snapshot,
            live_snapshot_identity,
            runtime_snapshot_token,
        ))
    }

    /// The v1 section classification, plus the ADR-0142 preflight: the first
    /// interface-only neighbor needs `CAP_NET_RAW`, and neighbors that would
    /// share a link-local address must be able to. A refusal is an
    /// unsupported section, so the plan is rejected before any effect.
    fn classify_config_transaction(
        &self,
        diff: &crate::config::ConfigDiff,
        candidate: &Config,
    ) -> crate::config::ConfigTransactionSectionClassification {
        let mut classification = crate::config::classify_config_transaction_v1(diff);
        classification
            .unsupported_sections
            .extend(self.unnumbered_preflight(candidate).err());
        classification
    }

    fn finish_config_transaction_plan(
        &mut self,
        candidate: &mut Config,
        materialization: Option<&crate::config::ConfigDiff>,
        external_inputs: crate::config::ExternalInputsIdentity,
        live_snapshot: rustbgpd_rib::UpdateGroupSnapshot,
        live_snapshot_identity: [u8; 8],
        runtime_snapshot_token: String,
    ) -> Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError> {
        let mut committed_diff = crate::config::diff_config(&self.current_config, candidate);
        committed_diff.policy.external_inputs_identity = external_inputs;
        let operational_diff = materialization.unwrap_or(&committed_diff);
        // Transaction executors rebuild raw member edits and static reshape
        // impacts. Preserve their fresh-interface preflight while comparison
        // inventories retain accepted peers whose interface is absent.
        // A target is `(address, interface)`: neighbors that share a
        // link-local address are separate members.
        let fresh_targets: HashSet<(&str, Option<&str>)> = operational_diff
            .neighbors
            .added
            .iter()
            .map(|neighbor| (neighbor.address.as_str(), neighbor.interface.as_deref()))
            .chain(
                operational_diff
                    .neighbors
                    .changed
                    .iter()
                    .map(|neighbor| (neighbor.address.as_str(), neighbor.interface.as_deref())),
            )
            .chain(
                operational_diff
                    .effective_neighbor_impact
                    .iter()
                    .filter_map(|impact| {
                        (!impact.is_dynamic_range
                            && impact.kind
                                == crate::config::EffectiveNeighborImpactKind::SessionReshape)
                            .then_some((impact.address.as_str(), impact.interface.as_deref()))
                    }),
            )
            .collect();
        for neighbor in &candidate.neighbors {
            if fresh_targets.contains(&(neighbor.address.as_str(), neighbor.interface.as_deref())) {
                candidate.resolve_neighbor(neighbor).map_err(|error| {
                    RuntimeConfigTransactionPlanError::InvalidCandidate(error.to_string())
                })?;
            }
        }
        let update_group_impact = self
            .plan_update_group_impact(candidate, live_snapshot)
            .map_err(|error| match error {
                super::update_group_plan::UpdateGroupImpactPlanError::InvalidCandidate(message) => {
                    RuntimeConfigTransactionPlanError::InvalidCandidate(message)
                }
                super::update_group_plan::UpdateGroupImpactPlanError::Internal(message) => {
                    RuntimeConfigTransactionPlanError::Internal(message)
                }
            })?;
        let classification = self.classify_config_transaction(operational_diff, candidate);
        let status = if classification.is_noop() {
            RuntimeConfigTransactionStatus::Noop
        } else if classification.is_committable() {
            RuntimeConfigTransactionStatus::Committable
        } else {
            RuntimeConfigTransactionStatus::Rejected
        };
        let diff = runtime_config_diff_from_config_diff(
            operational_diff,
            materialization.map(|_| &committed_diff),
        )
        .map_err(RuntimeConfigTransactionPlanError::Internal)?;
        let mut human_text = format_transaction_plan_text(
            status,
            &classification.supported_sections,
            &classification.unsupported_sections,
            &classification.restart_required_sections,
        );
        if materialization.is_some() {
            human_text.push_str(
                "The RFC 8212 tuple is materialized to its exact unchanged effective posture.\n",
            );
        }
        // A committable candidate is bounded-rendered exactly once. Its token
        // hashes the canonical body slice from those exact bytes (excluding the
        // maintenance header), preserving the live kv2 token contract without
        // a second whole-config serialization.
        let (post_commit_runtime_snapshot_token, committed_candidate) = if status
            == RuntimeConfigTransactionStatus::Committable
        {
            let normalized = crate::config::persisted_config_document_bounded(candidate)
                .map_err(|error| RuntimeConfigTransactionPlanError::Internal(error.to_string()))?;
            let token = self
                .snapshot_key
                .token_with_normalized_document(&normalized, &live_snapshot_identity)
                .map_err(RuntimeConfigTransactionPlanError::Internal)?;
            (
                token,
                Some(rustbgpd_api::peer_types::RuntimeConfigTransactionCandidate::new(normalized)),
            )
        } else {
            let token = self
                .snapshot_key
                .token_with_context_bounded(candidate, &live_snapshot_identity)
                .map_err(RuntimeConfigTransactionPlanError::Internal)?;
            (token, None)
        };

        Ok(RuntimeConfigTransactionPlan {
            status,
            runtime_snapshot_token,
            post_commit_runtime_snapshot_token,
            committed_candidate,
            diff,
            supported_sections: classification.supported_sections,
            unsupported_sections: classification.unsupported_sections,
            restart_required_sections: classification.restart_required_sections,
            human_text,
            update_group_impact,
        })
    }

    /// Atomically validate a candidate `[[fib_tables]]` set against the live
    /// runtime config and, on success, commit it into `current_config`. Builds
    /// a probe config from `current_config`'s peer groups / neighbors with the
    /// candidate table set substituted in, runs the full validator (reserved /
    /// duplicate table ids, families, ECMP caps, peer-group references), and
    /// only assigns `current_config.fib_tables` if it passes. Because the peer
    /// manager runs commands serially, validate-then-commit here cannot
    /// interleave with a peer-group deletion — closing the TOCTOU where a delete
    /// would check a snapshot that doesn't yet reflect the in-flight table.
    pub(super) fn stage_fib_tables_candidate(
        &mut self,
        tables: &[FibTableSnapshot],
    ) -> Result<(), String> {
        let staged: Vec<crate::config::FibTableConfig> =
            tables.iter().map(fib_table_snapshot_to_config).collect();
        let mut probe = self.current_config.clone();
        probe.fib_tables.clone_from(&staged);
        probe
            .validate_structure()
            .map_err(|error| error.to_string())?;
        self.current_config.fib_tables = staged;
        Ok(())
    }

    /// Refresh the live config snapshot's `[[fib_tables]]` after a gRPC CRUD
    /// mutation acknowledged by the FIB reconciler, so `diff_runtime_config`
    /// (which compares against `current_config`) doesn't report the
    /// just-applied set as pending.
    pub(super) fn set_fib_tables_snapshot(&mut self, tables: &[FibTableSnapshot]) {
        self.current_config.fib_tables = tables.iter().map(fib_table_snapshot_to_config).collect();
        self.local_forwarding_state
            .publish_fib(&self.current_config.fib_tables);
    }
}

fn runtime_config_diff_from_config_diff(
    diff: &crate::config::ConfigDiff,
    materialized: Option<&crate::config::ConfigDiff>,
) -> Result<RuntimeConfigDiff, String> {
    let mut diff_value = crate::config::config_diff_json_value(diff);
    if let Some(materialized) = materialized {
        diff_value["has_informational_changes"] = serde_json::Value::Bool(true);
        diff_value["config_epoch"] = serde_json::to_value(materialized.config_epoch)
            .map_err(|error| format!("failed to serialize config epoch change: {error}"))?;
        diff_value["ebgp_requires_policy"] =
            serde_json::to_value(materialized.ebgp_requires_policy)
                .map_err(|error| format!("failed to serialize RFC 8212 policy change: {error}"))?;
        diff_value["informational"]["rfc8212_materialization"] = serde_json::json!({
            "config_epoch": &materialized.config_epoch,
            "ebgp_requires_policy": &materialized.ebgp_requires_policy,
            "route_behavior_changed": false,
        });
    }
    let diff_json = serde_json::to_string_pretty(&diff_value)
        .map_err(|error| format!("failed to serialize config diff: {error}"))?;
    let mut human_text = crate::config::format_config_diff(diff);
    if let Some(materialized) = materialized {
        human_text.push_str(&crate::config::format_rfc8212_transaction_materialization(
            materialized,
        ));
    }
    Ok(RuntimeConfigDiff {
        has_actionable_changes: diff.has_actionable_changes(),
        has_reload_applied_changes: diff.has_reload_applied_changes(),
        has_restart_required_changes: diff.has_restart_required_changes(),
        has_informational_changes: materialized.is_some() || diff.has_informational_changes(),
        has_any_changes: diff.has_any_changes(),
        human_text,
        diff_json,
    })
}

fn format_transaction_plan_text(
    status: RuntimeConfigTransactionStatus,
    supported_sections: &[String],
    unsupported_sections: &[String],
    restart_required_sections: &[String],
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    match status {
        RuntimeConfigTransactionStatus::Noop => out.push_str("No changes.\n"),
        RuntimeConfigTransactionStatus::Committable => {
            out.push_str("Config transaction is committable by v1.\n");
        }
        RuntimeConfigTransactionStatus::Rejected => {
            out.push_str("Config transaction is not committable by v1.\n");
        }
    }
    if !supported_sections.is_empty() {
        out.push_str("Supported sections:\n");
        for section in supported_sections {
            let _ = writeln!(out, "  - {section}");
        }
    }
    if !unsupported_sections.is_empty() {
        out.push_str("Unsupported sections:\n");
        for section in unsupported_sections {
            let _ = writeln!(out, "  - {section}");
        }
    }
    if !restart_required_sections.is_empty() {
        out.push_str("Restart-required sections:\n");
        for section in restart_required_sections {
            let _ = writeln!(out, "  - {section}");
        }
    }
    out
}

/// Test latch: a load whose candidate carries [`load_latch::MARKER`] blocks
/// until [`load_latch::release`], so a test can hold loads in flight for as
/// long as it needs. Only candidates with the marker are affected.
#[cfg(test)]
pub(super) mod load_latch {
    use std::sync::{Condvar, Mutex};

    pub(crate) const MARKER: &str = "# candidate-load-latch";

    /// (loads currently held, released)
    static STATE: Mutex<(usize, bool)> = Mutex::new((0, false));
    static CHANGED: Condvar = Condvar::new();

    pub(super) fn hold_if_marked(candidate_toml: &str) {
        if !candidate_toml.contains(MARKER) {
            return;
        }
        let mut state = STATE.lock().unwrap();
        state.0 += 1;
        CHANGED.notify_all();
        while !state.1 {
            state = CHANGED.wait(state).unwrap();
        }
        state.0 -= 1;
        CHANGED.notify_all();
    }

    pub(crate) fn arm() {
        *STATE.lock().unwrap() = (0, false);
    }

    /// Wait until `count` marked loads are held, at most `limit`.
    pub(crate) fn wait_held(count: usize, limit: std::time::Duration) -> bool {
        let state = STATE.lock().unwrap();
        let (state, _) = CHANGED
            .wait_timeout_while(state, limit, |state| state.0 < count)
            .unwrap();
        state.0 >= count
    }

    pub(crate) fn release() {
        STATE.lock().unwrap().1 = true;
        CHANGED.notify_all();
    }
}
