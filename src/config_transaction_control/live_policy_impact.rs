use tokio::sync::{mpsc, oneshot};

use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicRangeTarget, PeerManagerCommand, ResolvedPeerPolicy,
};
use rustbgpd_api::runtime_config_settlement::RuntimeConfigFenceReason;
use rustbgpd_api::server::ConfigTransactionApplyError;

use crate::config::{Config, Neighbor, diff_config};
use crate::peer_manager::{
    InternalCommand, TransactionConfigRollbackToken, TransactionConfigScope,
};

use super::{
    ApplyFailure, RuntimeConfigMutationProgress, combine_rollback_errors,
    commit_config_snapshot_stage, persist_candidate_config, reserve_persist_permit,
    restore_preloaded_config_snapshot, rollback_snapshot_after_error,
    stage_preloaded_config_snapshot,
};

/// Commit a live-impact policy/peer-group/global-chain transaction: stage the
/// candidate snapshot, re-apply the affected static neighbors' resolved chains
/// to their live sessions (capturing priors), persist, and roll back live +
/// snapshot on failure. Returns the number of live sessions re-evaluated.
pub(super) async fn commit_live_policy_impact_locked(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    config_tx: &mpsc::Sender<ConfigEvent>,
    candidate_toml: String,
    candidate: &Config,
    progress: &RuntimeConfigMutationProgress,
) -> Result<usize, ApplyFailure> {
    let permit = reserve_persist_permit(config_tx).await?;
    progress.begin_mutation();
    let rollback = stage_preloaded_config_snapshot(
        peer_mgr_internal_tx,
        Box::new(candidate.clone()),
        TransactionConfigScope::Full,
    )
    .await?;

    let targets = match resolve_live_policy_targets(rollback.previous(), candidate) {
        Ok(targets) => targets,
        Err(error) => {
            progress.begin_settling();
            return Err(rollback_snapshot_after_error(
                peer_mgr_internal_tx,
                rollback,
                error.into(),
            )
            .await);
        }
    };

    let priors = match send_apply_policy_impact_snapshot(peer_mgr_tx, targets).await {
        Ok(priors) => priors,
        Err(error) => {
            // The peer-manager command self-heals its live mutations on a
            // mid-fanout failure, so only the staged snapshot needs rollback.
            progress.begin_settling();
            return Err(rollback_snapshot_after_error(
                peer_mgr_internal_tx,
                rollback,
                error.into(),
            )
            .await);
        }
    };

    progress.begin_settling();
    if let Err(failure) = persist_candidate_config(permit, candidate_toml).await {
        if failure.fence_reason.is_some() {
            return Err(failure);
        }
        return Err(rollback_live_policy_and_snapshot(
            peer_mgr_tx,
            peer_mgr_internal_tx,
            priors,
            rollback,
            failure,
        )
        .await);
    }
    // Ambiguous-persistence window (a): candidate durable on disk from here on.
    commit_config_snapshot_stage(peer_mgr_tx).await?;
    Ok(priors.len())
}

#[derive(Default)]
pub(super) struct LivePolicyTargets {
    pub(super) static_targets: Vec<ResolvedPeerPolicy>,
    dynamic_ranges: Vec<DynamicRangeTarget>,
}

/// Build the resolved-chain apply set from a live-impact diff:
/// every static neighbor whose resolved import/export policy moved and every
/// dynamic range whose accepted live peers need candidate policy resolution.
pub(super) fn resolve_live_policy_targets(
    previous: &Config,
    candidate: &Config,
) -> Result<LivePolicyTargets, ConfigTransactionApplyError> {
    let diff = diff_config(previous, candidate);
    let candidate_by_addr: std::collections::HashMap<&str, &Neighbor> = candidate
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();
    let dynamic_range_by_key: std::collections::HashMap<_, _> = candidate
        .dynamic_neighbors
        .iter()
        .filter_map(|range| {
            crate::config::effective_prefix_str(&range.prefix).map(|key| (key, range))
        })
        .collect();
    let mut targets = LivePolicyTargets::default();
    for impact in &diff.effective_neighbor_impact {
        if !impact.kind.is_policy_chain() {
            // A committable live-impact plan only carries policy-chain-only
            // impacts; anything else is an internal inconsistency — fail closed
            // rather than silently skip.
            return Err(ConfigTransactionApplyError::Internal(format!(
                "live-policy executor received an unsupported impact for {}",
                impact.address
            )));
        }
        if impact.is_dynamic_range {
            let Some((addr, prefix_len)) = crate::config::effective_prefix_str(&impact.address)
            else {
                return Err(ConfigTransactionApplyError::Internal(format!(
                    "live-policy impact references invalid dynamic range {}",
                    impact.address
                )));
            };
            let Some(range) = dynamic_range_by_key.get(&(addr, prefix_len)) else {
                return Err(ConfigTransactionApplyError::Internal(format!(
                    "live-policy impact references dynamic range {} absent from the candidate",
                    impact.address
                )));
            };
            targets.dynamic_ranges.push(DynamicRangeTarget {
                addr,
                prefix_len,
                peer_group: range.peer_group.clone(),
            });
            continue;
        }
        let Some(neighbor) = candidate_by_addr.get(impact.address.as_str()) else {
            return Err(ConfigTransactionApplyError::Internal(format!(
                "live-policy impact references neighbor {} absent from the candidate",
                impact.address
            )));
        };
        let address = neighbor.address.parse().map_err(|error| {
            ConfigTransactionApplyError::InvalidArgument(format!(
                "invalid neighbor address {:?}: {error}",
                neighbor.address
            ))
        })?;
        let resolved = candidate
            .resolve_neighbor(neighbor)
            .map_err(|error| ConfigTransactionApplyError::InvalidArgument(error.to_string()))?;
        targets.static_targets.push(ResolvedPeerPolicy {
            address,
            interface: neighbor.interface.clone(),
            import_policy: resolved.import_policy,
            export_policy: resolved.export_policy,
        });
    }
    Ok(targets)
}

/// Send `ApplyPolicyImpactSnapshot` and return the captured prior chains.
async fn send_apply_policy_impact_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    targets: LivePolicyTargets,
) -> Result<Vec<ResolvedPeerPolicy>, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ApplyPolicyImpactSnapshot {
            static_targets: targets.static_targets,
            dynamic_ranges: targets.dynamic_ranges,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable(
                "peer manager dropped policy-impact reply".to_string(),
            )
        })?
        .map_err(ConfigTransactionApplyError::Internal)
}

/// Send `ApplyResolvedPolicySnapshot` and return the captured prior chains.
/// Used in reverse to restore captured priors during rollback.
async fn send_apply_resolved_policy_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    targets: Vec<ResolvedPeerPolicy>,
) -> Result<Vec<ResolvedPeerPolicy>, ConfigTransactionApplyError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets,
            reply: reply_tx,
        })
        .await
        .map_err(|_| {
            ConfigTransactionApplyError::Unavailable("peer manager is unavailable".to_string())
        })?;
    reply_rx
        .await
        .map_err(|_| ConfigTransactionApplyError::RecoveryRequired {
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
            message: "peer manager accepted resolved-policy apply but dropped its reply"
                .to_string(),
        })?
        .map_err(ConfigTransactionApplyError::Internal)
}

async fn rollback_live_policy_and_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    priors: Vec<ResolvedPeerPolicy>,
    rollback: TransactionConfigRollbackToken,
    original: ApplyFailure,
) -> ApplyFailure {
    if original.fence_reason.is_some() {
        return original;
    }
    let live_rollback = send_apply_resolved_policy_snapshot(peer_mgr_tx, priors)
        .await
        .map(|_| ());
    let snapshot_rollback = restore_preloaded_config_snapshot(peer_mgr_internal_tx, rollback).await;
    match (live_rollback, snapshot_rollback) {
        (Ok(()), Ok(())) => original,
        (live_result, snapshot_result) => combine_rollback_errors(
            &original.error,
            "live policy rollback",
            live_result.err(),
            snapshot_result.err(),
        ),
    }
}
