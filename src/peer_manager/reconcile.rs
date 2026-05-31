use std::collections::HashMap;

use rustbgpd_api::peer_types::{
    FibTableSnapshot, PeerKey, PeerManagerNeighborConfig, ReconcileFailure, ReconcileFailureKind,
    ReconcileResult, RuntimeConfigDiff,
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

        // Capture per-peer operator-runtime state that should survive
        // a delete-then-readd cycle. RFC 8326 graceful-shutdown
        // toggle: a static-peer config edit (e.g. `description` change)
        // triggers a delete+readd in this reconcile path; without
        // capturing the desired state by address, the freshly added
        // ManagedPeer would come up with `advertise_graceful_shutdown
        // = false`, silently dropping the toggle mid-maintenance and
        // re-emitting untagged routes on the next outbound tick.
        let preserved_gshut: HashMap<PeerKey, bool> = changed
            .iter()
            .filter_map(|cfg| {
                let peer = PeerKey::new(cfg.address, cfg.interface.clone());
                self.peers
                    .get(&peer)
                    .filter(|m| m.advertise_graceful_shutdown)
                    .map(|_| (peer, true))
            })
            .collect();

        // Remove peers
        for addr in &removed {
            if let Err(e) = self.delete_peer(addr.clone(), false).await {
                warn!(peer = %addr, error = %e, "reconcile: failed to remove peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Remove,
                    peer: addr.clone(),
                    error: e,
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
                    error: e,
                });
                continue;
            }
            if let Err(e) = self.add_peer(cfg.clone(), false).await {
                warn!(peer = %addr, error = %e, "reconcile: failed to re-add changed peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeAdd,
                    peer: addr,
                    error: e,
                });
            }
        }
        // Replay preserved RFC 8326 toggles onto the freshly added
        // peers. This goes through the same path as the operator's
        // `rustbgpctl gshut` so the live session bool, ManagedPeer
        // desired state, AND RIB refresh all advance in lockstep —
        // even though the new session is mid-bring-up, the desired
        // state is in place and the bool will be applied to the
        // session's first emission once it reaches Established.
        for (addr, enabled) in preserved_gshut {
            let label = addr.to_string();
            if let Err(e) = self.set_graceful_shutdown(Some(addr), enabled).await {
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
                    error: e,
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
    ) -> Result<RuntimeConfigDiff, String> {
        let candidate =
            Config::load_toml_with_diagnostics(candidate_toml, "candidate runtime config")?;
        let diff = crate::config::diff_config(&self.current_config, &candidate);
        let diff_json = serde_json::to_string_pretty(&crate::config::config_diff_json_value(&diff))
            .map_err(|error| format!("failed to serialize config diff: {error}"))?;
        Ok(RuntimeConfigDiff {
            has_actionable_changes: diff.has_actionable_changes(),
            has_reload_applied_changes: diff.has_reload_applied_changes(),
            has_restart_required_changes: diff.has_restart_required_changes(),
            has_informational_changes: diff.has_informational_changes(),
            has_any_changes: diff.has_any_changes(),
            human_text: crate::config::format_config_diff(&diff),
            diff_json,
        })
    }

    /// Validate a candidate `[[fib_tables]]` set against the live runtime
    /// config. Builds a config from `current_config`'s peer groups / neighbors
    /// with the candidate table set substituted in, then runs the full
    /// validator (reserved / duplicate table ids, families, ECMP caps, and
    /// peer-group references). Used by the gRPC FIB-table CRUD control path to
    /// reject bad input before it reaches the FIB reconciler.
    pub(super) fn validate_fib_tables_candidate(
        &self,
        tables: &[FibTableSnapshot],
    ) -> Result<(), String> {
        let mut candidate = self.current_config.clone();
        candidate.fib_tables = tables.iter().map(fib_table_snapshot_to_config).collect();
        candidate.validate().map_err(|error| error.to_string())
    }
}
