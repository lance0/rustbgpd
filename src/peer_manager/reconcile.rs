use std::collections::HashMap;

use rustbgpd_api::peer_types::{
    FibTableSnapshot, PeerKey, PeerManagerNeighborConfig, ReconcileFailure, ReconcileFailureKind,
    ReconcileResult, RuntimeConfigDiff, RuntimeConfigDiffError, RuntimeConfigTransactionPlan,
    RuntimeConfigTransactionPlanError, RuntimeConfigTransactionStatus,
};
use tracing::{info, warn};

use crate::config::Config;
use crate::policy_admin::fib_table_snapshot_to_config;

use super::PeerManager;

impl PeerManager {
    pub(super) async fn reconcile_peers(
        &mut self,
        added: Vec<PeerManagerNeighborConfig>,
        removed: Vec<PeerKey>,
        changed: Vec<PeerManagerNeighborConfig>,
    ) -> ReconcileResult {
        let mut result = ReconcileResult::default();
        let added_count = added.len();
        let removed_count = removed.len();
        let changed_count = changed.len();

        // Capture per-peer operator-runtime state that should survive a
        // delete-then-readd cycle. Runtime state is not encoded in the TOML
        // candidate, so SIGHUP reconcile must carry it across explicitly.
        let preserved_runtime_state: HashMap<PeerKey, (bool, bool)> = changed
            .iter()
            .filter_map(|cfg| {
                let peer = PeerKey::new(cfg.address, cfg.interface.clone());
                self.peers
                    .get(&peer)
                    .map(|managed| (peer, (managed.enabled, managed.advertise_graceful_shutdown)))
            })
            .collect();

        // Remove peers
        for addr in &removed {
            if let Err(e) = self.delete_peer(addr.clone(), false).await {
                warn!(peer = %addr, error = %e, "reconcile: failed to remove peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Remove,
                    peer: addr.clone(),
                    error: e.to_string(),
                });
            }
        }
        // Changed peers: delete then re-add
        for cfg in &changed {
            let addr = PeerKey::new(cfg.address, cfg.interface.clone());
            if let Err(e) = self
                .delete_peer_for_reconfigure(addr.clone(), cfg.tcp_ao.as_ref())
                .await
            {
                warn!(peer = %addr, error = %e, "reconcile: failed to remove changed peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeRemove,
                    peer: addr,
                    error: e.to_string(),
                });
                continue;
            }
            let was_enabled = preserved_runtime_state
                .get(&addr)
                .is_none_or(|(enabled, _)| *enabled);
            if let Err(e) = self
                .add_peer_with_admin_state(cfg.clone(), false, was_enabled)
                .await
            {
                warn!(peer = %addr, error = %e, "reconcile: failed to re-add changed peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeAdd,
                    peer: addr,
                    error: e.to_string(),
                });
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
            }
        }
        // Add new peers
        for cfg in added {
            let addr = PeerKey::new(cfg.address, cfg.interface.clone());
            if let Err(e) = self.add_peer(cfg, false).await {
                warn!(peer = %addr, error = %e, "reconcile: failed to add new peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Add,
                    peer: addr,
                    error: e.to_string(),
                });
            }
        }
        info!(
            added = added_count,
            removed = removed_count,
            changed = changed_count,
            failures = result.failures.len(),
            "peer reconciliation complete"
        );
        result
    }

    pub(super) fn diff_runtime_config(
        &self,
        candidate_toml: &str,
    ) -> Result<RuntimeConfigDiff, RuntimeConfigDiffError> {
        let candidate =
            Config::load_toml_with_diagnostics(candidate_toml, "candidate runtime config")
                .map_err(RuntimeConfigDiffError::InvalidCandidate)?;
        let diff = crate::config::diff_config(&self.current_config, &candidate);
        runtime_config_diff_from_config_diff(&diff, None).map_err(RuntimeConfigDiffError::Internal)
    }

    pub(super) async fn plan_config_transaction(
        &self,
        candidate_toml: &str,
        expected_runtime_snapshot_token: Option<&str>,
    ) -> Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError> {
        let (live_snapshot, live_snapshot_identity, runtime_snapshot_token) = self
            .config_transaction_plan_context(expected_runtime_snapshot_token)
            .await?;
        let mut candidate =
            Config::load_toml_with_diagnostics(candidate_toml, "candidate runtime config")
                .map_err(RuntimeConfigTransactionPlanError::InvalidCandidate)?;
        let materialization = crate::config::materialize_rfc8212_transaction_candidate(
            &self.current_config,
            &mut candidate,
        );
        self.finish_config_transaction_plan(
            &candidate,
            materialization.as_ref(),
            live_snapshot,
            live_snapshot_identity,
            runtime_snapshot_token,
        )
    }

    pub(super) async fn plan_preloaded_config_transaction(
        &self,
        candidate: &mut Config,
        expected_runtime_snapshot_token: Option<&str>,
    ) -> Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError> {
        let (live_snapshot, live_snapshot_identity, runtime_snapshot_token) = self
            .config_transaction_plan_context(expected_runtime_snapshot_token)
            .await?;
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
        );
        self.finish_config_transaction_plan(
            candidate,
            materialization.as_ref(),
            live_snapshot,
            live_snapshot_identity,
            runtime_snapshot_token,
        )
    }

    async fn config_transaction_plan_context(
        &self,
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
            .token_with_context(&self.current_config, &live_snapshot_identity)
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

    fn finish_config_transaction_plan(
        &self,
        candidate: &Config,
        materialization: Option<&crate::config::ConfigDiff>,
        live_snapshot: rustbgpd_rib::UpdateGroupSnapshot,
        live_snapshot_identity: [u8; 8],
        runtime_snapshot_token: String,
    ) -> Result<RuntimeConfigTransactionPlan, RuntimeConfigTransactionPlanError> {
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
        // Token the resulting live config would carry once this candidate is
        // committed. The apply path returns it so a client can chain a follow-up
        // apply without re-planning; computing it here keeps every token under
        // the peer-manager's key. For the v1 single-family surface the committed
        // state equals the candidate (full-snapshot families) or differs only in
        // the one staged family (FIB), which the candidate already reflects.
        let post_commit_runtime_snapshot_token = self
            .snapshot_key
            .token_with_context(candidate, &live_snapshot_identity)
            .map_err(RuntimeConfigTransactionPlanError::Internal)?;
        let committed_diff = crate::config::diff_config(&self.current_config, candidate);
        let operational_diff = materialization.unwrap_or(&committed_diff);
        let classification = crate::config::classify_config_transaction_v1(operational_diff);
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
        let committed_candidate = if status == RuntimeConfigTransactionStatus::Committable {
            Some(
                crate::config::persisted_config_document(candidate)
                    .map(rustbgpd_api::peer_types::RuntimeConfigTransactionCandidate::new)
                    .map_err(|error| {
                        RuntimeConfigTransactionPlanError::Internal(error.to_string())
                    })?,
            )
        } else {
            None
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
        probe.validate().map_err(|error| error.to_string())?;
        self.current_config.fib_tables = staged;
        Ok(())
    }

    /// Refresh the live config snapshot's `[[fib_tables]]` after a gRPC CRUD
    /// mutation acknowledged by the FIB reconciler, so `diff_runtime_config`
    /// (which compares against `current_config`) doesn't report the
    /// just-applied set as pending.
    pub(super) fn set_fib_tables_snapshot(&mut self, tables: &[FibTableSnapshot]) {
        self.current_config.fib_tables = tables.iter().map(fib_table_snapshot_to_config).collect();
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
