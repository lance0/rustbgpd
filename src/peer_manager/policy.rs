use std::collections::BTreeSet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::Poll;
use std::time::Instant;

use rustbgpd_api::peer_types::{
    CatalogMutationError, ConfigEvent, DynamicRangeTarget, ImportValidationDependency,
    PeerGroupDefinition, PeerKey, PeerManagerNeighborConfig, ResolvedPeerPolicy,
};
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::{
    ExportPolicyCohortOutcome, PeerExportPolicyReplacement, RibCommandError, RibUpdate,
};
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::config::{Config, ConfigError};
use crate::policy_admin::{
    NEIGHBOR_NOT_FOUND_REASON, api_peer_group_to_config, apply_config_event,
    neighbor_set_references, peer_group_references, policy_references,
};

use super::{ManagedPeer, PEER_POLICY_UPDATE_TIMEOUT, PEER_QUERY_TIMEOUT, PeerManager};

fn catalog_config_error(error: ConfigError) -> CatalogMutationError {
    match error {
        ConfigError::InvalidNeighborAddress { value, reason }
            if reason == NEIGHBOR_NOT_FOUND_REASON =>
        {
            CatalogMutationError::not_found(format!("neighbor {value} not found"))
        }
        ConfigError::UndefinedPolicy { name } => {
            CatalogMutationError::not_found(format!("policy {name} not found"))
        }
        ConfigError::UndefinedPeerGroup { name } => {
            CatalogMutationError::not_found(format!("peer group {name} not found"))
        }
        other => CatalogMutationError::invalid(other.to_string()),
    }
}

/// How `update_runtime_policies_for_peer_key` reacts when the Route Refresh
/// send fails after the session already acked the new policy.
///
/// The three variants exist to keep rollback correct on a compound failure.
/// The choice between them turns entirely on whether the peer's `AdjRibIn` was
/// actually moved off the prior policy — see `CapturedResolvedPolicy::forward_completed`.
#[derive(Clone, Copy)]
enum RefreshFailureHandling {
    /// Forward apply path: surface the failure to the caller and arm
    /// `pending_refresh` so the next call retries.
    Fatal,
    /// Rollback of a peer whose forward apply *completed* (`AdjRibIn` was moved to
    /// the new policy): the rollback must refresh back to the prior policy, so a
    /// failed rollback refresh re-arms `pending_refresh = true` to retry.
    BestEffortRearm,
    /// Rollback of a peer whose forward apply did *not* complete (`AdjRibIn` never
    /// left the prior policy): no refresh is actually needed, so restore the
    /// captured prior `pending_refresh` rather than arming a spurious retry.
    BestEffortRestorePrior { pending_refresh: bool },
}

/// A peer's pre-apply policy state, captured during a live-impact apply so a
/// later failure can roll the peer back to exactly where it was.
struct CapturedResolvedPolicy {
    policy: ResolvedPeerPolicy,
    pending_refresh: bool,
    pending_export_apply: bool,
    /// Whether this peer's forward apply fully succeeded. This is the load-
    /// bearing flag for rollback correctness: it is really a proxy for *"did
    /// this peer's `AdjRibIn` actually move off the prior policy?"*. A completed
    /// forward ran a successful Route Refresh, so its `AdjRibIn` is at the new
    /// policy and rollback must refresh it back (`RefreshFailureHandling::BestEffortRearm`).
    /// An incomplete forward (session never acked, or the forward refresh
    /// failed) left `AdjRibIn` on the prior policy, so rollback needs no refresh
    /// and only restores the captured prior pending state
    /// (`RefreshFailureHandling::BestEffortRestorePrior`). Do not collapse the
    /// two branches: the asymmetry is what keeps a compound (rollback-time)
    /// refresh failure from either leaving routes stale or arming a spurious retry.
    forward_completed: bool,
}

#[derive(Default)]
struct PolicyRollbackRibBudget {
    deadline: Option<tokio::time::Instant>,
}

impl PolicyRollbackRibBudget {
    fn deadline(&mut self) -> tokio::time::Instant {
        *self
            .deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + super::RIB_REPLY_TIMEOUT)
    }
}

struct PolicyRollbackPeerPlan {
    peer_key: PeerKey,
    export_restore: Option<(Option<PolicyChain>, bool)>,
    refresh_failure: Option<RefreshFailureHandling>,
    is_established: bool,
    restore_prior_pending: Option<(bool, bool)>,
}

type PolicyRollbackRibOutcome = (usize, Result<(), RibCommandError>);
type PolicyRollbackRibFuture =
    Pin<Box<dyn Future<Output = PolicyRollbackRibOutcome> + Send + 'static>>;

async fn first_poll_policy_rollback_rib(
    future: &mut PolicyRollbackRibFuture,
) -> Option<PolicyRollbackRibOutcome> {
    std::future::poll_fn(|cx| {
        let mut unconstrained = std::pin::pin!(tokio::task::unconstrained(future.as_mut()));
        let poll = unconstrained.as_mut().poll(cx);
        Poll::Ready(match poll {
            Poll::Ready(outcome) => Some(outcome),
            Poll::Pending => None,
        })
    })
    .await
}

struct RegisteredPolicyRollbackRib {
    deadline: tokio::time::Instant,
    refreshable: Vec<bool>,
    task: tokio::task::JoinHandle<Vec<PolicyRollbackRibOutcome>>,
}

fn metric_count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn import_validation_dependency_label(dependency: ImportValidationDependency) -> &'static str {
    match dependency {
        ImportValidationDependency::Rpki => "rpki",
        ImportValidationDependency::Aspa => "aspa",
    }
}

fn record_import_validation_refresh_metrics(
    metrics: &BgpMetrics,
    dependency: ImportValidationDependency,
    eligible: usize,
    refreshed: usize,
    skipped_not_established: usize,
    failed: usize,
) {
    let dependency_label = import_validation_dependency_label(dependency);
    metrics.record_validation_import_refresh(dependency_label, "eligible", metric_count(eligible));
    metrics.record_validation_import_refresh(
        dependency_label,
        "refreshed",
        metric_count(refreshed),
    );
    metrics.record_validation_import_refresh(
        dependency_label,
        "skipped_not_established",
        metric_count(skipped_not_established),
    );
    metrics.record_validation_import_refresh(dependency_label, "failed", metric_count(failed));
}

impl PeerManager {
    pub(super) fn peer_group_policy_only_update(
        &self,
        name: &str,
        definition: &PeerGroupDefinition,
    ) -> bool {
        let Some(existing) = self.current_config.peer_groups.get(name) else {
            return false;
        };
        let next = api_peer_group_to_config(definition.clone());
        let policy_changed = existing.import_policy != next.import_policy
            || existing.export_policy != next.export_policy
            || existing.import_policy_chain != next.import_policy_chain
            || existing.export_policy_chain != next.export_policy_chain;
        if !policy_changed {
            return false;
        }

        let mut existing_non_policy = existing.clone();
        let mut next_non_policy = next;
        existing_non_policy.import_policy.clear();
        existing_non_policy.export_policy.clear();
        existing_non_policy.import_policy_chain.clear();
        existing_non_policy.export_policy_chain.clear();
        next_non_policy.import_policy.clear();
        next_non_policy.export_policy.clear();
        next_non_policy.import_policy_chain.clear();
        next_non_policy.export_policy_chain.clear();
        existing_non_policy == next_non_policy
    }

    #[cfg(test)]
    pub(super) async fn update_runtime_policies(
        &mut self,
        address: IpAddr,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
    ) -> Result<(), String> {
        let Some(peer_key) = self.unique_peer_key_for_address(address) else {
            return Ok(());
        };
        self.update_runtime_policies_fatal(peer_key, import_policy, export_policy)
            .await
    }

    /// Forward-apply resolved chains to one live peer with fatal refresh
    /// handling — the seam LAN-341's `hot_update_peer` shares with the
    /// gRPC chain-edit paths (session hot-apply, Route Refresh,
    /// Adj-RIB-Out re-emit, `pending_*` retry carry).
    pub(super) async fn update_runtime_policies_fatal(
        &mut self,
        peer_key: PeerKey,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
    ) -> Result<(), String> {
        self.update_runtime_policies_for_peer_key(
            peer_key,
            import_policy,
            export_policy,
            RefreshFailureHandling::Fatal,
            None,
        )
        .await
    }

    /// Apply resolved import/export chains to a set of live peers, capturing each
    /// peer's prior chains for rollback. On the first per-peer apply failure it
    /// attempts to restore the peers already changed (newest first). A successful
    /// restore leaves nothing mutated; a compound rollback failure is returned
    /// and may leave per-peer retry intent armed. On success it returns the
    /// captured priors — the rollback token the transaction executor replays
    /// through this same path after a later persistence failure. Targets not
    /// currently in `self.peers` (e.g. a dynamic peer that disconnected) are
    /// skipped and absent from the returned priors. Does NOT touch
    /// `current_config`; snapshot staging owns that.
    pub(super) async fn apply_resolved_policy_snapshot(
        &mut self,
        targets: Vec<ResolvedPeerPolicy>,
    ) -> Result<Vec<ResolvedPeerPolicy>, String> {
        let mut rollback_rib_budget = PolicyRollbackRibBudget::default();
        let total_targets = targets.len();
        let mut seen = BTreeSet::new();
        let has_duplicate = targets
            .iter()
            .any(|target| !seen.insert(PeerKey::new(target.address, target.interface.clone())));
        if has_duplicate {
            return self
                .apply_resolved_policy_snapshot_authoritatively(targets, &mut rollback_rib_budget)
                .await
                .map(|captured| {
                    captured
                        .into_iter()
                        .map(|captured| captured.policy)
                        .collect()
                });
        }

        let cohort_mask = self.export_only_policy_cohort_mask(&targets).await;
        let cohort_targets = cohort_mask.iter().filter(|&&selected| selected).count();
        if cohort_targets < 2 {
            return self
                .apply_resolved_policy_snapshot_authoritatively(targets, &mut rollback_rib_budget)
                .await
                .map(|captured| {
                    captured
                        .into_iter()
                        .map(|captured| captured.policy)
                        .collect()
                });
        }

        let cohort = targets
            .iter()
            .zip(&cohort_mask)
            .filter_map(|(target, &selected)| selected.then_some(target))
            .collect::<Vec<_>>();
        let remainder_targets = total_targets - cohort_targets;
        let started = Instant::now();
        info!(
            total_targets,
            cohort_targets, remainder_targets, "partitioned resolved policy snapshot"
        );

        let Some(cohort_result) = self
            .try_apply_export_only_policy_cohort(&cohort, &mut rollback_rib_budget)
            .await
        else {
            // Defensive invariant fallback: no mutation occurs before this
            // helper returns `None`, so preserve original authoritative order.
            return self
                .apply_resolved_policy_snapshot_authoritatively(targets, &mut rollback_rib_budget)
                .await
                .map(|captured| {
                    captured
                        .into_iter()
                        .map(|captured| captured.policy)
                        .collect()
                });
        };
        let mut captured = cohort_result?;
        drop(cohort);
        let remainder = targets
            .into_iter()
            .zip(cohort_mask)
            .filter_map(|(target, selected)| (!selected).then_some(target))
            .collect();
        match self
            .apply_resolved_policy_snapshot_authoritatively(remainder, &mut rollback_rib_budget)
            .await
        {
            Ok(mut remainder_captured) => {
                captured.append(&mut remainder_captured);
                info!(
                    total_targets,
                    cohort_targets,
                    remainder_targets,
                    elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    "committed partitioned resolved policy snapshot"
                );
                Ok(captured
                    .into_iter()
                    .map(|captured| captured.policy)
                    .collect())
            }
            Err(remainder_error) => Err(
                match self
                    .restore_resolved_policies(captured, &mut rollback_rib_budget)
                    .await
                {
                    Ok(()) => format!(
                        "failed to apply authoritative policy remainder: {remainder_error}; \
                     committed cohort restored"
                    ),
                    Err(cohort_restore_error) => format!(
                        "failed to apply authoritative policy remainder: {remainder_error}; \
                     restoring committed cohort also failed: {cohort_restore_error}"
                    ),
                },
            ),
        }
    }

    /// Select the largest locally eligible export-only cohort, with a stable
    /// lowest-`PeerKey` tie-break, while preserving caller order inside both
    /// partitions. Only the winning pair is queried for Established state. The
    /// RIB independently revalidates runtime group identity, ownership,
    /// generation, and session state. If fewer than two winning members remain
    /// Established, the caller takes the wholly authoritative path rather than
    /// trying a runner-up cohort.
    pub(super) async fn export_only_policy_cohort_mask(
        &mut self,
        targets: &[ResolvedPeerPolicy],
    ) -> Vec<bool> {
        let mut selected = vec![false; targets.len()];
        let mut groups: Vec<(usize, usize, PeerKey)> = Vec::new();
        for (index, target) in targets.iter().enumerate() {
            let Some((installed, target_chain)) = self.local_export_only_policy_pair(target) else {
                continue;
            };
            let peer_key = PeerKey::new(target.address, target.interface.clone());
            let group = groups.iter().position(|(representative, _, _)| {
                self.local_export_only_policy_pair(&targets[*representative])
                    .is_some_and(|(group_installed, group_target)| {
                        group_installed == installed && group_target == target_chain
                    })
            });
            if let Some(group) = group {
                groups[group].1 = groups[group].1.saturating_add(1);
                if peer_key < groups[group].2 {
                    groups[group].2 = peer_key;
                }
            } else {
                groups.push((index, 1, peer_key));
            }
        }
        let mut winner: Option<(usize, usize, PeerKey)> = None;
        for (representative, count, min_peer_key) in groups {
            if count >= 2
                && winner.as_ref().is_none_or(|(_, best_count, best_key)| {
                    count > *best_count || (count == *best_count && min_peer_key < *best_key)
                })
            {
                winner = Some((representative, count, min_peer_key));
            }
        }
        let Some((representative, _, _)) = winner else {
            return selected;
        };
        let (winning_installed, winning_target) = self
            .local_export_only_policy_pair(&targets[representative])
            .expect("winning cohort representative remains locally eligible");
        let winning_installed = winning_installed.clone();
        let winning_target = winning_target.clone();

        for (index, target) in targets.iter().enumerate() {
            let peer_key = PeerKey::new(target.address, target.interface.clone());
            let Some((installed, target_chain)) = self.local_export_only_policy_pair(target) else {
                continue;
            };
            if installed != &winning_installed || target_chain != &winning_target {
                continue;
            }
            let commands = self
                .peers
                .get(&peer_key)
                .expect("locally eligible cohort peer exists")
                .handle
                .commands_sender();

            let established = self
                .await_with_readiness(rustbgpd_transport::PeerHandle::query_state_with(
                    commands,
                    PEER_QUERY_TIMEOUT,
                ))
                .await
                .is_some_and(|state| state.fsm_state == SessionState::Established);
            self.drain_readiness_queries().await;
            if !established {
                continue;
            }
            selected[index] = true;
        }

        selected
    }

    /// Local (no session round-trip) cohort eligibility: the peer exists, its
    /// export chain moves, and no prior retry intent is pending. The import
    /// chain is allowed to move too (LAN-462): cohort setup hot-applies that
    /// delta per member and defers its Route Refresh past the batched RIB
    /// commit, so an import+export reload no longer disqualifies the fleet.
    /// The returned pair stays export-only because only the export move keys
    /// cohort identity — the RIB batch touches nothing else.
    fn local_export_only_policy_pair<'a>(
        &'a self,
        target: &'a ResolvedPeerPolicy,
    ) -> Option<(&'a Option<PolicyChain>, &'a Option<PolicyChain>)> {
        let peer_key = PeerKey::new(target.address, target.interface.clone());
        let managed = self.peers.get(&peer_key)?;
        (managed.export_policy != target.export_policy
            && !managed.pending_refresh
            && !managed.pending_export_apply)
            .then_some((&managed.export_policy, &target.export_policy))
    }

    /// Apply targets one at a time in their supplied order. This is the
    /// authoritative transaction used for an unpartitioned snapshot and for a
    /// partition's stable remainder. It never recursively selects a cohort.
    async fn apply_resolved_policy_snapshot_authoritatively(
        &mut self,
        targets: Vec<ResolvedPeerPolicy>,
        rollback_rib_budget: &mut PolicyRollbackRibBudget,
    ) -> Result<Vec<CapturedResolvedPolicy>, String> {
        // Captured priors, in application order, for peers actually mutated.
        let mut applied: Vec<CapturedResolvedPolicy> = Vec::new();
        for target in targets {
            let peer_key = PeerKey::new(target.address, target.interface.clone());
            let prior = {
                let Some(managed) = self.peers.get(&peer_key) else {
                    // Not currently live — skip; absent from returned priors.
                    continue;
                };
                CapturedResolvedPolicy {
                    policy: ResolvedPeerPolicy {
                        address: target.address,
                        interface: target.interface.clone(),
                        import_policy: managed.import_policy.clone(),
                        export_policy: managed.export_policy.clone(),
                    },
                    pending_refresh: managed.pending_refresh,
                    pending_export_apply: managed.pending_export_apply,
                    forward_completed: false,
                }
            };
            applied.push(prior);
            let applied_idx = applied.len() - 1;
            if let Err(apply_error) = self
                .update_runtime_policies_for_peer_key(
                    peer_key,
                    target.import_policy.clone(),
                    target.export_policy.clone(),
                    RefreshFailureHandling::Fatal,
                    None,
                )
                .await
            {
                let restored = std::mem::take(&mut applied);
                return Err(
                    match self
                        .restore_resolved_policies(restored, rollback_rib_budget)
                        .await
                    {
                        Ok(()) => format!(
                            "failed to apply resolved policy to {}: {apply_error}; \
                         already-applied peers restored",
                            target.address
                        ),
                        Err(restore_error) => format!(
                            "failed to apply resolved policy to {}: {apply_error}; \
                         restoring already-applied peers also failed: {restore_error}",
                            target.address
                        ),
                    },
                );
            }
            applied[applied_idx].forward_completed = true;
        }
        Ok(applied)
    }

    /// Fast path for the dominant reload shape: two or more Established peers
    /// share one export-chain move. Session hot-apply still precedes the RIB
    /// commit, but one batched RIB command lets equivalent clean update-group
    /// members share transition work. A member's import chain may move too
    /// (LAN-462): the changed chain is hot-applied during setup through the
    /// same session command the authoritative per-peer path uses, and its
    /// Route Refresh is deferred until after the batched RIB commit, so an
    /// import+export reload no longer collapses the whole fleet onto the
    /// per-peer authoritative transaction.
    ///
    /// Returning `None` means the whole target set is ineligible and the
    /// caller must use the existing per-peer transaction unchanged. Returning
    /// `Some` means this method owns rollback and has preserved the same prior
    /// token contract as the ordinary path.
    #[expect(
        clippy::too_many_lines,
        reason = "the cohort transaction keeps session apply, RIB commit, and rollback ownership together"
    )]
    async fn try_apply_export_only_policy_cohort(
        &mut self,
        targets: &[&ResolvedPeerPolicy],
        rollback_rib_budget: &mut PolicyRollbackRibBudget,
    ) -> Option<Result<Vec<CapturedResolvedPolicy>, String>> {
        if targets.len() < 2 {
            return None;
        }
        let mut peer_keys = Vec::with_capacity(targets.len());
        let mut import_deltas = Vec::with_capacity(targets.len());
        let mut seen = BTreeSet::new();
        for target in targets {
            let peer_key = PeerKey::new(target.address, target.interface.clone());
            if !seen.insert(peer_key.clone()) {
                return None;
            }
            let managed = self.peers.get(&peer_key)?;
            if managed.export_policy == target.export_policy
                || managed.pending_refresh
                || managed.pending_export_apply
            {
                return None;
            }
            import_deltas.push(managed.import_policy != target.import_policy);
            peer_keys.push(peer_key);
        }

        // Pre-stage the shared destination group in the RIB without the
        // transition fence, so the fenced transition later finds it
        // `Maintained` and skips its full-table staging walk — the dominant
        // share of the reload wall during which queued churn stalls at
        // route-server scale. Best-effort: on any error the transition
        // stages the destination itself, exactly as before. This must
        // precede the session hot-applies so a failure here costs nothing.
        let prestaged = {
            let (reply_tx, reply_rx) = oneshot::channel();
            let send_result = self
                .rib_tx
                .send(RibUpdate::PrepareExportPolicyDestination {
                    peer: targets[0].address,
                    export_policy: targets[0].export_policy.clone(),
                    reply: reply_tx,
                })
                .await;
            match send_result {
                Err(_) => false,
                Ok(()) => matches!(self.await_with_readiness(reply_rx).await, Ok(Ok(()))),
            }
        };

        let mut captured = Vec::with_capacity(targets.len());
        for ((target, peer_key), &import_changed) in
            targets.iter().zip(&peer_keys).zip(&import_deltas)
        {
            let prior = {
                let managed = self
                    .peers
                    .get(peer_key)
                    .expect("cohort peer existed after establishment preflight");
                CapturedResolvedPolicy {
                    policy: ResolvedPeerPolicy {
                        address: target.address,
                        interface: target.interface.clone(),
                        import_policy: managed.import_policy.clone(),
                        export_policy: managed.export_policy.clone(),
                    },
                    pending_refresh: false,
                    pending_export_apply: false,
                    forward_completed: false,
                }
            };
            // LAN-462: hot-apply a changed import chain through the same
            // session command the authoritative per-peer path uses
            // (`update_import_policy`), but do NOT fire `soft_reset_in` here —
            // the Route Refresh is deferred until after the cohort RIB commit
            // (see the deferred-refresh phase below for the correctness
            // argument).
            if import_changed {
                let import_commands = self
                    .peers
                    .get(peer_key)
                    .expect("cohort peer existed before import hot-apply")
                    .handle
                    .commands_sender();
                let import_result = self
                    .await_with_readiness(
                        rustbgpd_transport::PeerHandle::update_import_policy_with(
                            import_commands,
                            target.import_policy.clone(),
                            PEER_POLICY_UPDATE_TIMEOUT,
                        ),
                    )
                    .await;
                if let Err(error) = import_result {
                    if prestaged {
                        self.discard_prepared_export_destination(targets[0]).await;
                    }
                    // Mirror the authoritative forward-import bail: bookkeeping
                    // retains the prior chain so the next call still sees the
                    // delta and retries, and `pending_refresh` carries the
                    // unfired refresh intent across the ambiguous session state
                    // (the command may have installed the new chain before its
                    // reply was lost). The export command was never sent for
                    // this member, so only already-captured peers need
                    // restoring.
                    if let Some(managed) = self.peers.get_mut(peer_key) {
                        managed.pending_refresh = true;
                    }
                    let prior_restore = self
                        .restore_resolved_policies(captured, rollback_rib_budget)
                        .await;
                    return Some(Err(match prior_restore {
                        Ok(()) => format!(
                            "failed to apply resolved policy to {}: import: {error}; already-applied peers restored",
                            target.address
                        ),
                        Err(restore_error) => format!(
                            "failed to apply resolved policy to {}: import: {error}; restoring already-applied peers also failed: {restore_error}",
                            target.address
                        ),
                    }));
                }
                self.peers
                    .get_mut(peer_key)
                    .expect("cohort peer existed after import hot-apply")
                    .import_policy
                    .clone_from(&target.import_policy);
            }
            let commands = self
                .peers
                .get(peer_key)
                .expect("cohort peer existed before export hot-apply")
                .handle
                .commands_sender();
            let apply_result = self
                .await_with_readiness(rustbgpd_transport::PeerHandle::update_export_policy_with(
                    commands,
                    target.export_policy.clone(),
                    PEER_POLICY_UPDATE_TIMEOUT,
                ))
                .await;
            if let Err(error) = apply_result {
                if prestaged {
                    self.discard_prepared_export_destination(targets[0]).await;
                }
                // A failed session command is not proof that the session kept
                // its prior chain (the reply may fail after a partial local
                // apply). Reassert the failing peer's prior chain first, then
                // unwind the already-acknowledged peers newest-first.
                let restore_commands = self
                    .peers
                    .get(peer_key)
                    .expect("cohort peer existed while restoring failed export hot-apply")
                    .handle
                    .commands_sender();
                let failing_restore = self
                    .await_with_readiness(
                        rustbgpd_transport::PeerHandle::update_export_policy_with(
                            restore_commands,
                            prior.policy.export_policy.clone(),
                            PEER_POLICY_UPDATE_TIMEOUT,
                        ),
                    )
                    .await
                    .map_err(|restore_error| {
                        format!("{} session restore failed: {restore_error}", target.address)
                    });
                // LAN-462: the failing member's import chain was already
                // acknowledged (and bookkeeping advanced) during setup, so
                // reassert its prior import chain too, unwinding in reverse
                // of the import-then-export forward order.
                let failing_import_restore = if import_changed {
                    let import_restore_commands = self
                        .peers
                        .get(peer_key)
                        .expect("cohort peer existed while restoring acked import hot-apply")
                        .handle
                        .commands_sender();
                    match self
                        .await_with_readiness(
                            rustbgpd_transport::PeerHandle::update_import_policy_with(
                                import_restore_commands,
                                prior.policy.import_policy.clone(),
                                PEER_POLICY_UPDATE_TIMEOUT,
                            ),
                        )
                        .await
                    {
                        Ok(()) => {
                            self.peers
                                .get_mut(peer_key)
                                .expect("cohort peer existed after import restore")
                                .import_policy
                                .clone_from(&prior.policy.import_policy);
                            // The session ran the NEW import chain from the
                            // setup hot-apply until this reassert, so routes
                            // accepted in that window sit in Adj-RIB-In/LocRib
                            // evaluated under the wrong chain. Reconcile it the
                            // way the deferred-refresh phase does: fire the
                            // refresh now when Established, otherwise arm
                            // `pending_refresh` for the retry pipeline.
                            let refresh_commands = self
                                .peers
                                .get(peer_key)
                                .expect("cohort peer existed after import restore")
                                .handle
                                .commands_sender();
                            let established = self
                                .await_with_readiness(
                                    rustbgpd_transport::PeerHandle::query_state_with(
                                        refresh_commands,
                                        PEER_QUERY_TIMEOUT,
                                    ),
                                )
                                .await
                                .is_some_and(|state| state.fsm_state == SessionState::Established);
                            self.drain_readiness_queries().await;
                            let refreshed = established
                                && match self.soft_reset_in(peer_key.clone(), Vec::new()).await {
                                    Ok(()) => true,
                                    Err(refresh_error) => {
                                        warn!(
                                            peer = %peer_key,
                                            error = %refresh_error,
                                            "post-reassert route refresh failed after cohort export apply failure; arming pending refresh"
                                        );
                                        false
                                    }
                                };
                            if !refreshed && let Some(managed) = self.peers.get_mut(peer_key) {
                                managed.pending_refresh = true;
                            }
                            Ok(())
                        }
                        Err(restore_error) => {
                            // Cross-side carry (the authoritative bail
                            // discipline): the session may hold either chain,
                            // bookkeeping stays on the new one so a retry sees
                            // the delta, and `pending_refresh` keeps the
                            // unfired refresh intent armed.
                            if let Some(managed) = self.peers.get_mut(peer_key) {
                                managed.pending_refresh = true;
                            }
                            Err(format!(
                                "{} import restore failed: {restore_error}",
                                target.address
                            ))
                        }
                    }
                } else {
                    Ok(())
                };
                let prior_restore = self
                    .restore_resolved_policies(captured, rollback_rib_budget)
                    .await;
                let restore_error = [failing_restore, failing_import_restore, prior_restore]
                    .into_iter()
                    .filter_map(Result::err)
                    .reduce(|folded, error| format!("{folded}; {error}"));
                return Some(Err(match restore_error {
                    None => format!(
                        "failed to apply resolved policy to {}: export: {error}; already-applied peers restored",
                        target.address
                    ),
                    Some(restore_error) => format!(
                        "failed to apply resolved policy to {}: export: {error}; restoring already-applied peers also failed: {restore_error}",
                        target.address
                    ),
                }));
            }
            self.peers
                .get_mut(peer_key)
                .expect("cohort peer existed after export hot-apply")
                .export_policy
                .clone_from(&target.export_policy);
            captured.push(prior);
            self.drain_readiness_queries().await;
        }

        let replacements: Vec<_> = targets
            .iter()
            .map(|target| PeerExportPolicyReplacement {
                peer: target.address,
                export_policy: target.export_policy.clone(),
            })
            .collect();
        let (reply_tx, reply_rx) = oneshot::channel();
        let send_result = self
            .rib_tx
            .send(RibUpdate::ReplacePeerExportPolicies {
                replacements: replacements.clone(),
                reply: reply_tx,
            })
            .await;
        let cohort_result = match send_result {
            Err(_) => Err("RIB manager unavailable".to_string()),
            Ok(()) => self.await_export_policy_cohort_rib_reply(reply_rx).await,
        };
        let rib_result = match cohort_result {
            Ok(ExportPolicyCohortOutcome::Committed) => Ok(()),
            Ok(ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply) => {
                // A fallback that never reached the transition's staging
                // phase leaves the prepared destination unowned; remove it
                // before the per-peer applies rebuild membership through the
                // ordinary join path (memberless-only removal, so this is a
                // no-op whenever the group is actually in use).
                if prestaged {
                    self.discard_prepared_export_destination(targets[0]).await;
                }
                self.apply_export_policy_replacements_authoritatively(&replacements)
                    .await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = rib_result {
            if prestaged {
                self.discard_prepared_export_destination(targets[0]).await;
            }
            let rollback = self
                .restore_resolved_policies(captured, rollback_rib_budget)
                .await;
            return Some(Err(match rollback {
                Ok(()) => format!(
                    "failed to update export policy cohort: {error}; already-applied peers restored"
                ),
                Err(restore_error) => format!(
                    "failed to update export policy cohort: {error}; restoring already-applied peers also failed: {restore_error}"
                ),
            }));
        }

        // LAN-462: fire the deferred Route Refresh for members whose import
        // chain moved, now that the cohort RIB commit (or its authoritative
        // handoff) succeeded. Correctness: the window where the session runs
        // the new import chain while Adj-RIB-In still holds routes accepted
        // under the old one already exists today in the authoritative
        // per-peer path, between the import hot-apply and the peer's refresh
        // answer; deferring the refresh past the commit only lengthens that
        // window by seconds and converges identically once the peer
        // re-sends. The re-ingest is output-neutral whenever the import
        // change does not alter stored routes (LocRib suppresses
        // interned-attr-equal replacements). Members whose import chain was
        // unchanged get no refresh at all, exactly as today.
        for (index, (target, peer_key)) in targets.iter().zip(&peer_keys).enumerate() {
            if !import_deltas[index] {
                captured[index].forward_completed = true;
                continue;
            }
            let commands = self
                .peers
                .get(peer_key)
                .expect("cohort peer existed before deferred refresh")
                .handle
                .commands_sender();
            let established = self
                .await_with_readiness(rustbgpd_transport::PeerHandle::query_state_with(
                    commands,
                    PEER_QUERY_TIMEOUT,
                ))
                .await
                .is_some_and(|state| state.fsm_state == SessionState::Established);
            self.drain_readiness_queries().await;
            if established {
                if let Err(error) = self.soft_reset_in(peer_key.clone(), Vec::new()).await {
                    // Mirror the authoritative path's fatal refresh handling:
                    // arm `pending_refresh` for the retry pipeline, then
                    // unwind the snapshot. `forward_completed` stays false for
                    // this member and the ones after it — their sessions have
                    // been running the new import chain since the setup
                    // hot-apply, and the restore fires their refresh-back
                    // through the ordinary `import_changed` path when it
                    // reasserts the prior chain; the false flag only selects
                    // the failure-handling restore variant
                    // (`RefreshFailureHandling::BestEffortRestorePrior` plus
                    // the prior pending-flag restore) over the
                    // committed-forward `BestEffortRearm` one.
                    if let Some(managed) = self.peers.get_mut(peer_key) {
                        managed.pending_refresh = true;
                    }
                    let rollback = self
                        .restore_resolved_policies(captured, rollback_rib_budget)
                        .await;
                    return Some(Err(match rollback {
                        Ok(()) => format!(
                            "failed to apply resolved policy to {}: route refresh: {error}; already-applied peers restored",
                            target.address
                        ),
                        Err(restore_error) => format!(
                            "failed to apply resolved policy to {}: route refresh: {error}; restoring already-applied peers also failed: {restore_error}",
                            target.address
                        ),
                    }));
                }
            } else {
                // Idle/Connect (nothing in Adj-RIB-In yet) or an ambiguous
                // state query: arm `pending_refresh` so a later call fires the
                // refresh once the session is reachable — the same handling
                // the authoritative path applies to a non-Established peer.
                if let Some(managed) = self.peers.get_mut(peer_key) {
                    managed.pending_refresh = true;
                }
            }
            captured[index].forward_completed = true;
        }
        Some(Ok(captured))
    }

    /// Fire-and-forget cleanup of a prepared clean-transition destination
    /// after the cohort failed before its transition committed. The RIB only
    /// removes a memberless group, so a race with a committed transition is
    /// harmless — callers still restrict this to pre-commit failure paths.
    async fn discard_prepared_export_destination(&self, target: &ResolvedPeerPolicy) {
        let _ = self
            .rib_tx
            .send(RibUpdate::DiscardPreparedExportPolicyDestination {
                peer: target.address,
                export_policy: target.export_policy.clone(),
            })
            .await;
    }

    /// Await the cohort RIB reply while admitting only the dedicated
    /// read-only readiness lane. The ordinary command receiver stays owned by
    /// the run loop and is not polled, so mutations remain strictly behind the
    /// transaction. Dropping the transaction caller does not cancel a
    /// partially applied policy: this actor still drives commit or rollback to
    /// completion before returning to the normal lane.
    async fn await_export_policy_cohort_rib_reply(
        &mut self,
        reply_rx: oneshot::Receiver<Result<ExportPolicyCohortOutcome, String>>,
    ) -> Result<ExportPolicyCohortOutcome, String> {
        match self.await_with_readiness(reply_rx).await {
            Err(_) => Err("RIB manager dropped cohort reply".to_string()),
            Ok(result) => result,
        }
    }

    /// Complete a cohort handoff through the ordinary authoritative RIB seam.
    ///
    /// Session chains were already applied during cohort setup. Sending one
    /// ordinary RIB replacement at a time avoids a second session hot-apply,
    /// keeps the next peer out of the RIB queue until the prior peer replies,
    /// and admits the dedicated readiness lane throughout each send/reply.
    async fn apply_export_policy_replacements_authoritatively(
        &mut self,
        replacements: &[PeerExportPolicyReplacement],
    ) -> Result<(), String> {
        for replacement in replacements {
            match self
                .replace_peer_export_policy_in_rib(
                    replacement.peer,
                    replacement.export_policy.clone(),
                )
                .await
            {
                Ok(()) => {}
                Err(error @ RibCommandError::NotFound(_)) => {
                    info!(
                        peer = %replacement.peer,
                        %error,
                        "authoritative export-policy handoff skipped a peer no longer registered in the RIB; a reconnect will install the desired policy"
                    );
                }
                Err(error) => return Err(format!("{}: {error}", replacement.peer)),
            }
            self.drain_readiness_queries().await;
        }
        Ok(())
    }

    /// Run one ordinary RIB export-policy replacement while servicing the
    /// dedicated readiness lane and enforcing the existing five-second reply
    /// deadline.
    async fn replace_peer_export_policy_in_rib(
        &mut self,
        peer: IpAddr,
        export_policy: Option<PolicyChain>,
    ) -> Result<(), RibCommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let rib_tx = self.rib_tx.clone();
        if self
            .await_with_readiness(rib_tx.send(RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                reply: reply_tx,
            }))
            .await
            .is_err()
        {
            return Err(RibCommandError::internal("RIB manager unavailable"));
        }
        match tokio::time::timeout(
            super::RIB_REPLY_TIMEOUT,
            self.await_with_readiness(reply_rx),
        )
        .await
        {
            Err(_) => Err(RibCommandError::internal(format!(
                "RIB manager did not reply within {:?} while updating export policy",
                super::RIB_REPLY_TIMEOUT
            ))),
            Ok(Err(_)) => Err(RibCommandError::internal("RIB manager dropped reply")),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Ok(Ok(()))) => Ok(()),
        }
    }

    /// Apply a live-impact transaction that may include static neighbors and
    /// dynamic ranges. Dynamic ranges are expanded inside the peer manager
    /// against the accepted-range attribution captured on each live dynamic
    /// peer, then the full concrete target list is committed by the existing
    /// rollback-capable resolved-policy snapshot path.
    pub(super) async fn apply_policy_impact_snapshot(
        &mut self,
        mut static_targets: Vec<ResolvedPeerPolicy>,
        dynamic_ranges: Vec<DynamicRangeTarget>,
    ) -> Result<Vec<ResolvedPeerPolicy>, String> {
        let mut dynamic_targets = self.resolve_dynamic_policy_targets(&dynamic_ranges)?;
        static_targets.append(&mut dynamic_targets);
        self.apply_resolved_policy_snapshot(static_targets).await
    }

    fn resolve_dynamic_policy_targets(
        &self,
        dynamic_ranges: &[DynamicRangeTarget],
    ) -> Result<Vec<ResolvedPeerPolicy>, String> {
        if dynamic_ranges.is_empty() {
            return Ok(Vec::new());
        }

        let mut peer_keys: Vec<PeerKey> = self.peers.keys().cloned().collect();
        peer_keys.sort();
        let mut targets = Vec::new();
        for peer_key in peer_keys {
            let Some(managed) = self.peers.get(&peer_key) else {
                continue;
            };
            if !managed.is_dynamic {
                continue;
            }
            let Some(accepted) = managed.accepted_dynamic_range.as_ref() else {
                continue;
            };
            let Some(target_range) = dynamic_ranges.iter().find(|target| {
                target.addr == accepted.addr
                    && target.prefix_len == accepted.prefix_len
                    && target.peer_group == accepted.peer_group
            }) else {
                continue;
            };
            let Some(group) = self
                .current_config
                .peer_groups
                .get(&target_range.peer_group)
            else {
                return Err(format!(
                    "dynamic range {}/{} references missing peer_group {:?}",
                    target_range.addr, target_range.prefix_len, target_range.peer_group
                ));
            };
            let resolved = self
                .current_config
                .resolve_dynamic_neighbor(
                    peer_key.address,
                    managed.remote_asn,
                    &managed.description,
                    group,
                    &target_range.peer_group,
                )
                .map_err(|error| {
                    format!(
                        "failed to resolve dynamic peer {} for range {}/{}: {error}",
                        peer_key, target_range.addr, target_range.prefix_len
                    )
                })?;
            targets.push(ResolvedPeerPolicy {
                address: peer_key.address,
                interface: peer_key.interface.clone(),
                import_policy: resolved.import_policy,
                export_policy: resolved.export_policy,
            });
        }
        Ok(targets)
    }

    async fn register_policy_rollback_rib(
        &self,
        plans: &[PolicyRollbackPeerPlan],
        budget: &mut PolicyRollbackRibBudget,
    ) -> Option<RegisteredPolicyRollbackRib> {
        let mut futures = Vec::new();
        for (index, plan) in plans.iter().enumerate() {
            let Some((export_policy, _)) = &plan.export_restore else {
                continue;
            };
            let rib_tx = self.rib_tx.clone();
            let peer = plan.peer_key.address;
            let export_policy = export_policy.clone();
            let future: PolicyRollbackRibFuture = Box::pin(async move {
                let (reply_tx, reply_rx) = oneshot::channel();
                let result = if rib_tx
                    .send(RibUpdate::ReplacePeerExportPolicy {
                        peer,
                        export_policy,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    Err(RibCommandError::internal("RIB manager unavailable"))
                } else {
                    match reply_rx.await {
                        Ok(result) => result,
                        Err(_) => Err(RibCommandError::internal("RIB manager dropped reply")),
                    }
                };
                (index, result)
            });
            futures.push((index, future));
        }
        if futures.is_empty() {
            return None;
        }

        let deadline = budget.deadline();
        let mut completed = Vec::new();
        let mut pending = Vec::new();
        let mut refreshable = vec![false; plans.len()];
        for (index, mut future) in futures {
            // Poll every reverse-order send once without Tokio's cooperative
            // budget. A full bounded channel therefore registers every waiter
            // in FIFO order before rollback can emit a Route Refresh, time out,
            // or return control to a later PeerManager mutation.
            let first_poll = first_poll_policy_rollback_rib(&mut future).await;
            if let Some(outcome) = first_poll {
                refreshable[index] = match &outcome.1 {
                    Ok(()) => true,
                    Err(RibCommandError::NotFound(_)) => plans[index]
                        .export_restore
                        .as_ref()
                        .is_some_and(|(_, is_known_non_established)| *is_known_non_established),
                    Err(_) => false,
                };
                completed.push(outcome);
            } else {
                // The send either reached the RIB and awaits its reply, or
                // owns its FIFO place in a full channel. Keep the import
                // rollback moving: this pinned future survives the caller
                // deadline and remains ahead of refresh-generated RIB work.
                refreshable[index] = true;
                pending.push(future);
            }
        }

        let task = tokio::spawn(async move {
            completed.extend(futures::future::join_all(pending).await);
            completed
        });
        Some(RegisteredPolicyRollbackRib {
            deadline,
            refreshable,
            task,
        })
    }

    async fn finish_policy_rollback_refresh(&mut self, plan: &PolicyRollbackPeerPlan) {
        let Some(refresh_failure) = plan.refresh_failure else {
            return;
        };
        let pending_after = if plan.is_established {
            match self.soft_reset_in(plan.peer_key.clone(), Vec::new()).await {
                Ok(()) => plan
                    .restore_prior_pending
                    .is_some_and(|(pending_refresh, _)| pending_refresh),
                Err(error) => {
                    warn!(
                        peer = %plan.peer_key.address,
                        %error,
                        "route refresh failed during policy rollback; retained safe pending state"
                    );
                    match refresh_failure {
                        RefreshFailureHandling::Fatal | RefreshFailureHandling::BestEffortRearm => {
                            true
                        }
                        RefreshFailureHandling::BestEffortRestorePrior { pending_refresh } => {
                            pending_refresh
                        }
                    }
                }
            }
        } else {
            match refresh_failure {
                RefreshFailureHandling::Fatal | RefreshFailureHandling::BestEffortRearm => true,
                RefreshFailureHandling::BestEffortRestorePrior { pending_refresh } => {
                    pending_refresh
                }
            }
        };
        if let Some(managed) = self.peers.get_mut(&plan.peer_key) {
            managed.pending_refresh = pending_after;
        }
    }

    fn finish_policy_rollback_rib_success(&mut self, plan: &PolicyRollbackPeerPlan) {
        let Some(managed) = self.peers.get_mut(&plan.peer_key) else {
            return;
        };
        if let Some((pending_refresh, pending_export_apply)) = plan.restore_prior_pending {
            managed.pending_refresh = pending_refresh;
            managed.pending_export_apply = pending_export_apply;
        } else {
            managed.pending_export_apply = false;
        }
    }

    fn retain_policy_rollback_rib_intent(&mut self, plan: &PolicyRollbackPeerPlan) {
        if let Some(managed) = self.peers.get_mut(&plan.peer_key) {
            managed.pending_export_apply = true;
            if plan.refresh_failure.is_some() {
                managed.pending_refresh = true;
            }
        }
    }

    async fn finish_policy_rollback_refreshes(
        &mut self,
        plans: &[PolicyRollbackPeerPlan],
        registered: Option<&RegisteredPolicyRollbackRib>,
    ) {
        for (index, plan) in plans.iter().enumerate() {
            let refreshable = plan.export_restore.is_none()
                || registered.is_some_and(|registered| registered.refreshable[index]);
            if refreshable {
                self.finish_policy_rollback_refresh(plan).await;
            }
            if plan.export_restore.is_none() {
                self.finish_policy_rollback_rib_success(plan);
            }
        }
    }

    /// Re-apply captured prior chains (reverse of application order) to restore
    /// live peers during a transaction rollback. Session/bookkeeping restores
    /// run first. Every required RIB send is then registered in reverse order
    /// before any Route Refresh, and all RIB sends/replies share one lazy
    /// absolute deadline across this top-level policy transaction. Timing out or
    /// dropping the caller detaches the exact registered aggregate so FIFO repair
    /// can continue while conservative pending flags retain retry intent.
    async fn restore_resolved_policies(
        &mut self,
        priors: Vec<CapturedResolvedPolicy>,
        budget: &mut PolicyRollbackRibBudget,
    ) -> Result<(), String> {
        let mut errors: Vec<String> = Vec::new();
        let mut plans = Vec::new();
        for prior in priors.into_iter().rev() {
            let address = prior.policy.address;
            let peer_key = PeerKey::new(address, prior.policy.interface.clone());
            if !self.peers.contains_key(&peer_key) {
                continue;
            }
            let refresh_failure = if prior.forward_completed {
                RefreshFailureHandling::BestEffortRearm
            } else {
                RefreshFailureHandling::BestEffortRestorePrior {
                    pending_refresh: prior.pending_refresh,
                }
            };
            let mut plan = None;
            match self
                .update_runtime_policies_for_peer_key(
                    peer_key,
                    prior.policy.import_policy,
                    prior.policy.export_policy,
                    refresh_failure,
                    Some(&mut plan),
                )
                .await
            {
                Err(error) => errors.push(format!("{address}: {error}")),
                Ok(()) => {
                    if let Some(mut plan) = plan {
                        if !prior.forward_completed {
                            plan.restore_prior_pending =
                                Some((prior.pending_refresh, prior.pending_export_apply));
                        }
                        plans.push(plan);
                    }
                }
            }
        }

        let registered = self.register_policy_rollback_rib(&plans, budget).await;
        self.finish_policy_rollback_refreshes(&plans, registered.as_ref())
            .await;

        if let Some(registered) = registered {
            match tokio::time::timeout_at(
                registered.deadline,
                self.await_with_readiness(registered.task),
            )
            .await
            {
                Err(_) => {
                    for plan in plans.iter().filter(|plan| plan.export_restore.is_some()) {
                        self.retain_policy_rollback_rib_intent(plan);
                    }
                    errors.push(format!(
                        "rollback RIB restores exceeded the shared {:?} deadline; late ordered repair continues",
                        super::RIB_REPLY_TIMEOUT
                    ));
                }
                Ok(Err(error)) => {
                    for plan in plans.iter().filter(|plan| plan.export_restore.is_some()) {
                        self.retain_policy_rollback_rib_intent(plan);
                    }
                    errors.push(format!("rollback RIB restore task failed: {error}"));
                }
                Ok(Ok(outcomes)) => {
                    for (index, outcome) in outcomes {
                        let plan = &plans[index];
                        match outcome {
                            Ok(()) => self.finish_policy_rollback_rib_success(plan),
                            Err(error @ RibCommandError::NotFound(_))
                                if plan.export_restore.as_ref().is_some_and(
                                    |(_, is_known_non_established)| *is_known_non_established,
                                ) =>
                            {
                                info!(
                                    peer = %plan.peer_key.address,
                                    %error,
                                    "policy rollback found no RIB outbound registration; the restored session policy will be authoritative on PeerUp"
                                );
                                self.finish_policy_rollback_rib_success(plan);
                            }
                            Err(error) => {
                                self.retain_policy_rollback_rib_intent(plan);
                                errors.push(format!("{}: {error}", plan.peer_key.address));
                            }
                        }
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub(super) async fn soft_reset_import_validation_dependents(
        &self,
        dependency: ImportValidationDependency,
    ) -> Result<(), String> {
        let candidates: Vec<PeerKey> = self
            .peers
            .iter()
            .filter_map(|(peer_key, managed)| {
                let depends_on_cache =
                    managed
                        .import_policy
                        .as_ref()
                        .is_some_and(|chain| match dependency {
                            ImportValidationDependency::Rpki => chain.requires_rpki_validation(),
                            ImportValidationDependency::Aspa => chain.requires_aspa_validation(),
                        });
                depends_on_cache.then(|| peer_key.clone())
            })
            .collect();

        let mut refreshed = 0usize;
        let mut skipped_not_established = 0usize;
        let mut failures = Vec::new();

        for peer_key in &candidates {
            let Some(managed) = self.peers.get(peer_key) else {
                continue;
            };
            let state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
            if !state
                .as_ref()
                .is_some_and(|s| s.fsm_state == SessionState::Established)
            {
                skipped_not_established += 1;
                continue;
            }

            let refresh_result = tokio::time::timeout(
                PEER_POLICY_UPDATE_TIMEOUT,
                self.soft_reset_in(peer_key.clone(), Vec::new()),
            )
            .await;
            match refresh_result {
                Ok(Ok(())) => refreshed += 1,
                Ok(Err(error)) => {
                    warn!(
                        peer = %peer_key,
                        ?dependency,
                        error = %error,
                        "failed to refresh validation-dependent import policy after cache update"
                    );
                    failures.push(format!("{peer_key}: {error}"));
                }
                Err(_) => {
                    let error =
                        format!("route refresh timed out after {PEER_POLICY_UPDATE_TIMEOUT:?}");
                    warn!(
                        peer = %peer_key,
                        ?dependency,
                        error = %error,
                        "timed out refreshing validation-dependent import policy after cache update"
                    );
                    failures.push(format!("{peer_key}: {error}"));
                }
            }
        }

        record_import_validation_refresh_metrics(
            &self.metrics,
            dependency,
            candidates.len(),
            refreshed,
            skipped_not_established,
            failures.len(),
        );

        info!(
            ?dependency,
            eligible = candidates.len(),
            refreshed,
            skipped_not_established,
            failures = failures.len(),
            "processed validation-cache import-policy refresh"
        );

        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "validation-cache import refresh failed for {} of {} eligible peers: {}",
                failures.len(),
                candidates.len(),
                failures.join("; ")
            ))
        }
    }

    /// LAN-305: dependency-scoped refresh after dataset content swaps.
    /// Mirrors [`Self::soft_reset_import_validation_dependents`] (the
    /// RPKI/ASPA cache-update pattern): only peers whose chains
    /// structurally reference a swapped dataset are touched — Route
    /// Refresh inbound where the *import* chain references one (the
    /// peer re-sends, routes re-evaluate against the new generation),
    /// forced outbound re-emission (`RibUpdate::RefreshPeerOutbound`)
    /// where the *export* chain does. Chains are never replaced:
    /// they share the swapped handles, so counters, generations, and
    /// unrelated peers are untouched. `failed` datasets (prior
    /// snapshot retained) are counted into
    /// `bgp_policy_dataset_refresh_errors_total`.
    #[expect(
        clippy::too_many_lines,
        reason = "one linear pass: failure metrics, candidate scoping, then the import/export refresh legs"
    )]
    pub(super) async fn refresh_dataset_dependents(
        &self,
        swapped: &[String],
        failed: &[(String, String)],
    ) -> Result<(), String> {
        for (dataset, reason) in failed {
            warn!(
                dataset = %dataset,
                error = %reason,
                "dataset refresh failed; prior snapshot still serving"
            );
            self.metrics.record_policy_dataset_refresh_error(dataset);
        }
        // ADR-0110 freshness: each swapped dataset was just accepted —
        // stamp its loaded timestamp. Failed refreshes above deliberately
        // keep their last-accepted timestamp so `time() - <gauge>` ages.
        for dataset in swapped {
            self.metrics.record_policy_dataset_loaded(dataset);
        }
        if swapped.is_empty() {
            return Ok(());
        }
        let references_any = |chain: &Option<rustbgpd_policy::PolicyChain>| {
            chain
                .as_ref()
                .is_some_and(|chain| swapped.iter().any(|name| chain.references_dataset(name)))
        };
        let candidates: Vec<(PeerKey, bool, bool)> = self
            .peers
            .iter()
            .filter_map(|(peer_key, managed)| {
                let import = references_any(&managed.import_policy);
                let export = references_any(&managed.export_policy);
                (import || export).then(|| (peer_key.clone(), import, export))
            })
            .collect();

        let mut failures = Vec::new();
        let mut refreshed = 0usize;
        let mut skipped_not_established = 0usize;
        for (peer_key, import, export) in &candidates {
            let Some(managed) = self.peers.get(peer_key) else {
                continue;
            };
            let state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
            if !state
                .as_ref()
                .is_some_and(|s| s.fsm_state == SessionState::Established)
            {
                // Nothing in AdjRibIn/Out yet; the session evaluates
                // against the current generation when it comes up.
                skipped_not_established += 1;
                continue;
            }
            if *import {
                match tokio::time::timeout(
                    PEER_POLICY_UPDATE_TIMEOUT,
                    self.soft_reset_in(peer_key.clone(), Vec::new()),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => failures.push(format!("{peer_key} (import): {error}")),
                    Err(_) => failures.push(format!(
                        "{peer_key} (import): route refresh timed out after {PEER_POLICY_UPDATE_TIMEOUT:?}"
                    )),
                }
            }
            if *export {
                let (reply_tx, reply_rx) = oneshot::channel();
                let outcome = if self
                    .rib_tx
                    .send(RibUpdate::RefreshPeerOutbound {
                        peer: peer_key.address,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    Err("RIB manager unavailable".to_string())
                } else {
                    match tokio::time::timeout(super::RIB_REPLY_TIMEOUT, reply_rx).await {
                        Ok(Ok(result)) => result,
                        Ok(Err(_)) => Err("RIB manager dropped reply".to_string()),
                        Err(_) => Err(format!(
                            "RIB manager did not reply within {:?}",
                            super::RIB_REPLY_TIMEOUT
                        )),
                    }
                };
                if let Err(error) = outcome {
                    failures.push(format!("{peer_key} (export): {error}"));
                }
            }
            refreshed += 1;
        }
        info!(
            swapped = ?swapped,
            eligible = candidates.len(),
            refreshed,
            skipped_not_established,
            failures = failures.len(),
            "processed dataset-swap dependency-scoped refresh"
        );
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "dataset refresh failed for {} of {} referencing peers: {}",
                failures.len(),
                candidates.len(),
                failures.join("; ")
            ))
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn update_runtime_policies_for_peer_key(
        &mut self,
        peer_key: PeerKey,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        refresh_failure: RefreshFailureHandling,
        rollback_plan: Option<&mut Option<PolicyRollbackPeerPlan>>,
    ) -> Result<(), String> {
        use std::fmt::Write as _;
        let address = peer_key.address;
        let Some(managed) = self.peers.get_mut(&peer_key) else {
            return Ok(());
        };

        // Capture the *prior* import policy before clobbering so we
        // can decide at the end whether to issue a Route Refresh.
        // `update_import_policy_timeout` only swaps the policy
        // reference for *future* inbound UPDATEs — routes already in
        // AdjRibIn were accepted under the old policy and stay there
        // until the peer re-advertises. Without an automatic refresh
        // here, a permit→deny edit silently leaves forbidden routes
        // flowing.
        let import_changed = managed.import_policy != import_policy;
        let export_changed = managed.export_policy != export_policy;

        // Drain any pending refresh / pending export-apply from a
        // prior call. If a previous round wanted to retry but the
        // session-side update failed (or the peer wasn't Established
        // yet for the import refresh), we re-arm so this call retries
        // in lockstep with whatever new edits the current call brings.
        let had_pending_refresh = std::mem::take(&mut managed.pending_refresh);
        let had_pending_export_apply = std::mem::take(&mut managed.pending_export_apply);

        // Bounded deadlines on the per-peer session round-trips. Without
        // them a back-pressured peer parks the peer-manager actor here,
        // which then can't service `ListPeers` (or any other command), so
        // a `GetHealth` RPC issued during the reload would wedge for as
        // long as the back-pressure lasts. Same wedge class fixed by
        // `query_state_timeout` for the read path; this closes the
        // hot-apply path.
        //
        // Hot-apply to the session FIRST and defer advancing
        // `managed.import_policy` / `managed.export_policy` until the
        // session acknowledges. If the session-side update fails (task
        // back-pressured past the deadline, task exited, mpsc full),
        // leaving the daemon's bookkeeping at the prior value lets the
        // next call's `import_changed` / `export_changed` comparisons
        // still see a delta and retry. The previous "advance
        // bookkeeping then warn-and-continue on session error" pattern
        // allowed the daemon to believe the new policy was live while
        // the session task still held the old one — and worse, would
        // then fire Route Refresh against the session, which would
        // re-evaluate AdjRibIn against the *old* policy and silently
        // keep forbidden routes flowing.
        //
        // A side whose resolved chain is CONTENT-EQUAL to the installed
        // one (`PolicyChain: PartialEq` — the same equality the
        // update-group registry keys on) is skipped entirely: no
        // session command, so no import-generation bump and no term-hit
        // counter reset on a peer an rpol/catalog edit didn't actually
        // touch. Every reinstall fan-out (SIGHUP rpol overlay, catalog
        // edits, the ADR-0076 txn executor, honor-knob toggles) routes
        // through here, so this is the one place the scoping lives.
        // Mirror the export-side ambiguous-reply repair below. A failed
        // forward import command may have installed the new chain before its
        // reply was lost. Rollback bookkeeping still names the prior chain,
        // so equality alone cannot prove the session has it. Reassert the
        // prior import chain before any rollback Route Refresh whenever the
        // incomplete forward attempt carried refresh intent.
        let reassert_prior_import = had_pending_refresh
            && matches!(
                refresh_failure,
                RefreshFailureHandling::BestEffortRestorePrior { .. }
            );
        let import_apply_result = if import_changed || reassert_prior_import {
            managed
                .handle
                .update_import_policy_timeout(import_policy.clone(), PEER_POLICY_UPDATE_TIMEOUT)
                .await
        } else {
            Ok(())
        };
        let import_apply_failed = if let Err(error) = &import_apply_result {
            warn!(
                %address,
                error = %error,
                "failed to hot-apply import policy to peer session; retaining prior policy in daemon bookkeeping for retry"
            );
            true
        } else {
            if import_changed {
                managed.import_policy = import_policy;
            }
            false
        };

        // A failed forward export command is not proof that the session kept
        // its prior chain: the reply may be lost after a partial local apply.
        // During rollback, `managed.export_policy` deliberately still names the
        // prior chain, so equality alone would skip the reassertion and clear
        // the pending marker against an ambiguous session. Re-send the prior
        // chain before restoring the RIB whenever this incomplete-forward path
        // inherited export intent.
        let reassert_prior_export = had_pending_export_apply
            && matches!(
                refresh_failure,
                RefreshFailureHandling::BestEffortRestorePrior { .. }
            );
        let export_apply_result = if export_changed || reassert_prior_export {
            managed
                .handle
                .update_export_policy_timeout(export_policy.clone(), PEER_POLICY_UPDATE_TIMEOUT)
                .await
        } else {
            Ok(())
        };
        let export_apply_failed = if let Err(error) = &export_apply_result {
            warn!(
                %address,
                error = %error,
                "failed to hot-apply export policy to peer session; retaining prior policy in daemon bookkeeping for retry"
            );
            true
        } else {
            if export_changed {
                managed.export_policy.clone_from(&export_policy);
            }
            false
        };

        let session_state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
        let is_established = session_state
            .as_ref()
            .is_some_and(|s| s.fsm_state == SessionState::Established);
        let is_known_non_established = session_state
            .as_ref()
            .is_some_and(|s| s.fsm_state != SessionState::Established);

        let needs_refresh = import_changed || had_pending_refresh;
        let needs_export_apply = export_changed || had_pending_export_apply;

        // Bail before the RIB update and Route Refresh if either side
        // failed under an apply-changing intent. The bail decision is
        // not gated on `is_established` for either side: Route Refresh
        // is gated separately by `soft_reset_in`'s own Established
        // check, but the *failure-surfacing* decision is independent.
        // For non-Established peers the same staleness exists — the
        // session task may eventually drop the queued command (task
        // dies before processing) and reach Established holding the
        // prior policy. Without bailing, `apply_policy_change` would
        // advance `current_config`, leaving no signal that the edit
        // didn't actually land.
        //
        //   - Import bail: session didn't acknowledge the new import
        //     policy under refresh intent. For Established peers this
        //     also prevents firing Route Refresh against a session
        //     that still holds the prior policy, which would
        //     re-evaluate AdjRibIn against the *old* policy.
        //
        //   - Export bail: session didn't acknowledge the new export
        //     policy under export-apply intent. Letting bookkeeping
        //     advance here would (a) leave the peer announcing under
        //     the prior export policy until something else triggered
        //     a re-apply, and (b) drift the RIB's view
        //     (`ReplacePeerExportPolicy`) away from the session's
        //     view if we proceeded to the RIB update step.
        //
        // Set the matching pending flag(s) so the next call retries,
        // then return Err so the caller (gRPC reply, SIGHUP reload
        // halt path) surfaces the failure rather than logging-and-
        // forgetting.
        let import_bail = import_apply_failed && needs_refresh;
        let export_bail = export_apply_failed && needs_export_apply;
        if import_bail || export_bail {
            if let Some(managed) = self.peers.get_mut(&peer_key) {
                // Carry forward *all* unfired apply / refresh intent
                // across the bail, not just the side that triggered
                // the bail. Critical cross-side case: import-apply
                // succeeded (so `managed.import_policy` already
                // advanced) but the export bail stops us before
                // `soft_reset_in`. If we only set the bail-triggering
                // flag, the next retry would see `import_changed =
                // false` (bookkeeping already advanced) and
                // `had_pending_refresh = false`, compute
                // `needs_refresh = false`, and silently skip Route
                // Refresh — leaving AdjRibIn routes accepted under
                // the prior import policy stuck against a session
                // that now has the new policy. Setting both flags
                // whenever the corresponding intent was present
                // makes the retry pipeline pick up *every* unfired
                // step regardless of which side bailed.
                if needs_refresh {
                    managed.pending_refresh = true;
                }
                if needs_export_apply {
                    managed.pending_export_apply = true;
                }
            }
            let mut detail = String::new();
            if import_bail {
                let import_err = import_apply_result
                    .as_ref()
                    .err()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default();
                let _ = write!(detail, "import: {import_err}");
            }
            if export_bail {
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                let export_err = export_apply_result
                    .as_ref()
                    .err()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default();
                let _ = write!(detail, "export: {export_err}");
            }
            return Err(format!(
                "policy hot-apply to peer {address} failed; retry deferred to next \
                 update_runtime_policies call: {detail}"
            ));
        }

        let is_rollback = !matches!(refresh_failure, RefreshFailureHandling::Fatal);
        if let Some(rollback_plan) = rollback_plan {
            debug_assert!(
                is_rollback,
                "rollback planning requires best-effort handling"
            );
            if let Some(managed) = self.peers.get_mut(&peer_key) {
                if needs_refresh {
                    managed.pending_refresh = true;
                }
                if needs_export_apply {
                    managed.pending_export_apply = true;
                }
            }
            *rollback_plan = Some(PolicyRollbackPeerPlan {
                peer_key,
                export_restore: needs_export_apply
                    .then_some((export_policy, is_known_non_established)),
                refresh_failure: needs_refresh.then_some(refresh_failure),
                is_established,
                restore_prior_pending: None,
            });
            return Ok(());
        }
        if needs_export_apply && (is_established || is_rollback) {
            // The RIB step sits between session-side hot-apply (already
            // succeeded if we reached here) and Route Refresh. If it
            // fails, we still need to preserve any unfired refresh
            // intent: bookkeeping has already advanced (because session
            // ACKed), so on the next call `import_changed` would be
            // false and `needs_refresh` would compute false without a
            // `pending_refresh` carry — the same silent-skip class as
            // the cross-side bail bug. Use explicit match so the Err
            // arms can re-arm `pending_refresh` before returning.
            //
            // Gated on export-apply intent (content moved, or a prior
            // call's unfired intent): re-sending a content-equal chain
            // would swap the RIB's installed instance out from under a
            // grouped peer's shared staging handle — the group keeps
            // evaluating (and counting term hits) on the old instance
            // while the stats query snapshots the fresh one, freezing
            // the reported counters.
            // A rollback cannot use the Established observation as a proxy for
            // RIB registration. A peer may flap after its forward apply while
            // its old outbound object is still registered, and skipping this
            // step would leave that object evaluating the policy being rolled
            // back. Try the authoritative restore even when the session query
            // positively reports a non-Established state. A typed NotFound is
            // safe only for rollback of such a known-down peer: there is no
            // outbound object left to retain the forward policy, and the next
            // PeerUp carries the restored policy from the session. A timed-out
            // state query remains ambiguous and therefore fail-closed, as do
            // forward applies and peers still reporting Established.
            let rib_outcome = self
                .replace_peer_export_policy_in_rib(address, export_policy)
                .await;
            match rib_outcome {
                Ok(()) => {}
                Err(error @ RibCommandError::NotFound(_))
                    if is_rollback && is_known_non_established =>
                {
                    info!(
                        %address,
                        %error,
                        "policy rollback found no RIB outbound registration; the restored session policy will be authoritative on PeerUp"
                    );
                }
                Err(error) => {
                    if let Some(managed) = self.peers.get_mut(&peer_key) {
                        managed.pending_export_apply = true;
                        if needs_refresh {
                            managed.pending_refresh = true;
                        }
                    }
                    return Err(error.to_string());
                }
            }
        } else if had_pending_export_apply || (needs_export_apply && !is_known_non_established) {
            // This ordinary call skipped the RIB. Preserve inherited intent
            // even for a known-down peer, and arm fresh intent when the state
            // query was ambiguous: that may be an Established peer whose RIB
            // still holds the prior chain. Only a positively known-down fresh
            // change can rely solely on PeerUp installing the current session
            // policy without a retry marker.
            if let Some(managed) = self.peers.get_mut(&peer_key) {
                managed.pending_export_apply = true;
            }
        }

        // Issue Route Refresh (RFC 2918) to re-evaluate routes already
        // in this peer's AdjRibIn against the new import policy.
        // Driven from here rather than from the SIGHUP-only reload
        // path so dynamic peers, gRPC mutations, and any other call
        // site that goes through `apply_policy_change` get the same
        // correctness guarantee — the loop above iterates
        // `self.peers`, which includes dynamic peers.
        //
        // Gated on (a) the import policy materially changing — re-
        // applying the same chain (no-op edits, redundant mutations)
        // shouldn't trigger Route Refresh storms — and (b) the
        // session being Established. Idle / Connect-state peers
        // have nothing in AdjRibIn yet; they'll receive routes
        // under the new policy when the session reaches
        // Established naturally. Without the Established gate,
        // `send_route_refresh` would error for any non-Established
        // peer ("session not Established"), and an operator gRPC
        // `SetPolicy` issued while one of N peers is mid-reconnect
        // would fail.
        //
        // Failure for an Established peer bubbles up to
        // `apply_policy_change`'s caller — for SIGHUP reloads, that
        // halts the reload via `halt_partial` so the failure is
        // surfaced rather than logged-and-forgotten. Before bubbling
        // up, set `pending_refresh` so the next operator action
        // retries the refresh — otherwise a single transient send
        // failure (peer task mid-restart, mpsc backpressure) would
        // leave the new policy applied to *future* UPDATEs while
        // routes already in AdjRibIn keep flowing under the prior
        // policy until the operator reissues a SetPolicy.
        if needs_refresh && is_established {
            if let Err(error) = self.soft_reset_in(peer_key.clone(), Vec::new()).await {
                match refresh_failure {
                    RefreshFailureHandling::Fatal => {
                        if let Some(managed) = self.peers.get_mut(&peer_key) {
                            managed.pending_refresh = true;
                        }
                        return Err(error.to_string());
                    }
                    RefreshFailureHandling::BestEffortRearm => {
                        if let Some(managed) = self.peers.get_mut(&peer_key) {
                            managed.pending_refresh = true;
                        }
                        warn!(
                            %address,
                            error = %error,
                            "route refresh failed during policy rollback; armed pending_refresh"
                        );
                    }
                    RefreshFailureHandling::BestEffortRestorePrior { pending_refresh } => {
                        if let Some(managed) = self.peers.get_mut(&peer_key) {
                            managed.pending_refresh = pending_refresh;
                        }
                        warn!(
                            %address,
                            error = %error,
                            "route refresh failed while restoring a failed policy apply; restored prior pending_refresh state"
                        );
                    }
                }
            }
        } else if needs_refresh {
            // `!is_established` here means one of: the peer really is
            // Idle / Connect / OpenSent (no AdjRibIn to refresh — the
            // refresh next call would be a no-op), OR
            // `query_state_timeout` returned None for an
            // actually-Established peer (back-pressured session task
            // missed the deadline) and we cannot distinguish the two
            // from this side. Re-arm `pending_refresh` unconditionally
            // so that a subsequent call — once the session unblocks
            // or the peer reaches Established — fires the refresh.
            // Without this, a fresh `import_changed = true` in this
            // call combined with a stale state query would silently
            // drop refresh intent: bookkeeping advances, the retry
            // sees `import_changed = false`, and AdjRibIn routes
            // accepted under the prior policy stay stuck. The
            // wasted-refresh cost on a genuinely Idle peer (next call
            // sends Route Refresh against an empty / freshly-populated
            // AdjRibIn) is small and acceptable next to silent
            // staleness.
            if let Some(managed) = self.peers.get_mut(&peer_key) {
                managed.pending_refresh = match refresh_failure {
                    RefreshFailureHandling::BestEffortRestorePrior { pending_refresh } => {
                        pending_refresh
                    }
                    RefreshFailureHandling::Fatal | RefreshFailureHandling::BestEffortRearm => true,
                };
            }
        }

        Ok(())
    }

    pub(super) async fn apply_policy_change(
        &mut self,
        event: ConfigEvent,
        affected_peers: Option<Vec<IpAddr>>,
    ) -> Result<(), CatalogMutationError> {
        if let ConfigEvent::DeletePolicy { name, .. } = &event {
            let refs = policy_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(CatalogMutationError::StillReferenced {
                    kind: "policy",
                    name: name.clone(),
                    references: refs,
                });
            }
        }
        if let ConfigEvent::DeleteNeighborSet { name, .. } = &event {
            let refs = neighbor_set_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(CatalogMutationError::StillReferenced {
                    kind: "neighbor set",
                    name: name.clone(),
                    references: refs,
                });
            }
        }
        // ADR-0096: TOML definitions and .rpol policies share one
        // namespace; creating a TOML definition that shadows an .rpol
        // policy would silently change every chain referencing it.
        if let ConfigEvent::SetPolicy { name, .. } = &event
            && let Some(entry) = self.current_config.policy.rpol.policies.get(name)
        {
            return Err(CatalogMutationError::internal(format!(
                "policy {name:?} is defined by rpol file {:?}; \
                 rpol and TOML policies share one namespace",
                entry.path
            )));
        }

        let mut next_config = self.current_config.clone();
        apply_config_event(&mut next_config, &event).map_err(catalog_config_error)?;

        let applied = self
            .refresh_policies_for_config(next_config, affected_peers)
            .await?;
        self.publish_policy_config_event(&event, applied);
        Ok(())
    }

    /// ADR-0096: adopt a new compiled `.rpol` registry (SIGHUP reload
    /// of `[policy] rpol_files` or of referenced file content) and
    /// re-resolve every live peer's chains through it, using the same
    /// resolve-first, rollback-capable fan-out as catalog policy edits. Peers
    /// whose import chain materially changed get a Route Refresh inside
    /// `apply_resolved_policy_snapshot`.
    pub(super) async fn sync_rpol_policies(
        &mut self,
        rpol_files: Vec<String>,
        rpol: rustbgpd_policy::rpol::RpolPolicySet,
        dataset_bindings: rustbgpd_policy::datasets::DatasetBindings,
    ) -> Result<(), CatalogMutationError> {
        let mut next_config = self.current_config.clone();
        next_config.policy.rpol_files = rpol_files;
        next_config.policy.rpol = rpol;
        // LAN-305: the new registry's `dataset` declarations resolve
        // through these handles during the chain re-resolution below.
        next_config.policy.dataset_bindings = dataset_bindings;
        let applied = self.refresh_policies_for_config(next_config, None).await?;
        info!(
            peers = applied,
            "rpol policy registry replaced; live peer chains re-resolved"
        );
        Ok(())
    }

    /// Shared catalog-change fan-out: resolve every affected peer's
    /// chains against `next_config`, commit them through the rollback-capable
    /// resolved-policy snapshot path, then adopt `next_config` as the
    /// manager's snapshot. Returns the number of peers whose chains
    /// were applied.
    async fn refresh_policies_for_config(
        &mut self,
        next_config: Config,
        affected_peers: Option<Vec<IpAddr>>,
    ) -> Result<usize, CatalogMutationError> {
        let peers: Vec<PeerKey> = affected_peers.map_or_else(
            || self.peers.keys().cloned().collect(),
            |peers| {
                peers
                    .into_iter()
                    .flat_map(|address| self.peer_keys_for_address(address))
                    .collect()
            },
        );
        // Resolve every affected peer's chains BEFORE mutating anything, then
        // commit the whole set through the rollback-capable resolved-policy
        // snapshot path (the ADR-0076 live-impact executor's capturing mechanism).
        // The two-phase shape rejects a resolution failure with zero peers
        // touched. A mid-fanout apply failure attempts to restore already-updated
        // peers to their captured priors; a compound rollback failure is surfaced
        // and may leave the existing per-peer retry intent armed.
        let mut targets: Vec<ResolvedPeerPolicy> = Vec::new();
        for peer_key in peers {
            let Some(managed) = self.peers.get(&peer_key) else {
                continue;
            };
            let is_dynamic = managed.is_dynamic;
            let address = peer_key.address;
            // Static neighbors resolve from their `[[neighbors]]` record.
            // Dynamic peers have no record — resolve their chains through
            // the synthetic peer-group-backed neighbor (the honor-knob
            // pattern) instead of skipping them; otherwise catalog edits
            // never reach live dynamic sessions until they flap, and a
            // route server runs split-brain policy between sessions
            // accepted before and after the edit.
            let record = next_config.neighbors.iter().find(|neighbor| {
                neighbor.address == address.to_string() && neighbor.interface == peer_key.interface
            });
            let neighbor = match record {
                Some(neighbor) => neighbor.clone(),
                None if is_dynamic => {
                    Self::policy_resolution_neighbor(&next_config, address, managed)
                }
                None => continue,
            };
            let chains = next_config.effective_policy_chains_for_neighbor(&neighbor);
            let (import_policy, export_policy) = match chains {
                Ok(chains) => chains,
                // An orphaned dynamic peer (accepted range deleted, then its
                // peer group deleted) has no resolvable chains; its session
                // keeps the chains it already runs. Don't fail the whole
                // catalog mutation for it — static-resolution failures stay
                // fatal because they indicate the event itself is broken.
                Err(error) if is_dynamic => {
                    warn!(
                        peer = %address,
                        %error,
                        "catalog change: dynamic peer chains unresolvable; \
                         session keeps its prior chains"
                    );
                    continue;
                }
                Err(error) => return Err(catalog_config_error(error)),
            };
            targets.push(ResolvedPeerPolicy {
                address,
                interface: peer_key.interface.clone(),
                import_policy,
                export_policy,
            });
        }
        let applied = self
            .apply_resolved_policy_snapshot(targets)
            .await
            .map_err(CatalogMutationError::internal)?;

        // ADR-0110 freshness: adopting `next_config` is the accept moment
        // for this policy generation. Sync the per-dataset series against
        // the new binding set: a dataset introduced by this apply gets a
        // loaded timestamp; one removed from config gets its series reaped
        // (content bumps are stamped on the RefreshDatasetDependents path).
        // A rejected apply returns above without stamping anything.
        for handle in next_config.policy.dataset_bindings.handles() {
            if self
                .current_config
                .policy
                .dataset_bindings
                .get(handle.name())
                .is_none()
            {
                self.metrics.record_policy_dataset_loaded(handle.name());
            }
        }
        for handle in self.current_config.policy.dataset_bindings.handles() {
            if next_config
                .policy
                .dataset_bindings
                .get(handle.name())
                .is_none()
            {
                self.metrics.reap_policy_dataset_series(handle.name());
            }
        }
        self.metrics.record_policy_generation_loaded();
        self.current_config = next_config;
        self.invalidate_stale_dynamic_max_prefix_restarts();
        Ok(applied.len())
    }

    pub(super) fn policy_resolution_neighbor(
        config: &Config,
        address: IpAddr,
        managed: &ManagedPeer,
    ) -> crate::config::Neighbor {
        config
            .neighbors
            .iter()
            .find(|neighbor| {
                neighbor.address == address.to_string()
                    && neighbor.interface == managed.transport_config.peer_interface
            })
            .cloned()
            .unwrap_or_else(|| crate::config::Neighbor {
                address: address.to_string(),
                interface: managed.transport_config.peer_interface.clone(),
                remote_asn: managed.remote_asn,
                description: None,
                peer_group: managed.peer_group.clone(),
                hold_time: None,
                send_hold_time: None,
                slow_peer_threshold_pct: None,
                slow_peer_duration: None,
                slow_peer_isolation: None,
                max_prefixes: None,
                max_prefixes_ipv4: None,
                max_prefixes_ipv6: None,
                max_prefix_restart_seconds: None,
                md5_password: None,
                tcp_ao: None,
                bfd: None,
                ttl_security: None,
                families: Vec::new(),
                required_families: Vec::new(),
                graceful_restart: None,
                gr_restart_time: None,
                gr_peer_restart_time_max: None,
                gr_stale_routes_time: None,
                llgr_stale_time: None,
                local_ipv6_nexthop: None,
                route_reflector_client: None,
                orr_vantage: None,
                route_server_client: None,
                per_client_best: None,
                next_hop_ownership: None,
                interpret_rfc1997: None,
                rs_control_communities: None,
                role: None,
                strict_role: None,
                prefix_orf_receive: None,
                disable_ipv4_unicast: None,
                remove_private_as: None,
                add_path: None,
                log_level: None,
                import_policy: Vec::new(),
                export_policy: Vec::new(),
                import_policy_chain: Vec::new(),
                export_policy_chain: Vec::new(),
            })
    }

    pub(super) async fn set_honor_graceful_shutdown(
        &mut self,
        enabled: bool,
    ) -> Result<(), String> {
        if self.current_config.global.honor_graceful_shutdown == enabled {
            return Ok(());
        }

        // Best-effort fan-out: precompute every EBGP peer's resolved chains
        // against the *new* snapshot, advance the snapshot unconditionally,
        // then iterate applying. A failure on peer B must not leave peer A
        // running with the new effective policy while `current_config`
        // still shows the old knob value — that drift is what the prior
        // `?`-shortcircuit shape produced and is hard to debug
        // operationally. Failed peers will pick up the stale state on
        // their next `update_runtime_policies` call thanks to the
        // existing bail-and-carry plumbing (`pending_refresh` /
        // `pending_export_apply` flags retry on the next policy edit).
        //
        // Resolution failures are also non-fatal at the per-peer scope:
        // if a single neighbor's effective chain can't be resolved
        // (e.g. peer-group reference broken mid-flight), other peers
        // shouldn't be punished for it.
        let mut next_config = self.current_config.clone();
        next_config.global.honor_graceful_shutdown = enabled;

        let targets: Vec<PeerKey> = self
            .peers
            .iter()
            .filter_map(|(peer, managed)| {
                (managed.remote_asn != self.local_asn).then_some(peer.clone())
            })
            .collect();

        let mut failures: Vec<String> = Vec::new();
        for peer_key in targets {
            let address = peer_key.address;
            let Some(managed) = self.peers.get(&peer_key) else {
                continue;
            };
            let neighbor = Self::policy_resolution_neighbor(&next_config, address, managed);
            let chains = next_config.effective_policy_chains_for_neighbor(&neighbor);
            let (import_policy, export_policy) = match chains {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        %address,
                        error = %e,
                        "honor_graceful_shutdown: failed to resolve effective chain — skipping peer"
                    );
                    failures.push(format!("{address}: chain-resolve: {e}"));
                    continue;
                }
            };
            if let Err(e) = self
                .update_runtime_policies_for_peer_key(
                    peer_key,
                    import_policy,
                    export_policy,
                    RefreshFailureHandling::Fatal,
                    None,
                )
                .await
            {
                warn!(
                    %address,
                    error = %e,
                    "honor_graceful_shutdown: failed to hot-apply on peer — desired snapshot \
                     advances anyway; bail-and-carry will retry on next policy edit"
                );
                failures.push(format!("{address}: hot-apply: {e}"));
            }
        }

        // Snapshot advances regardless of per-peer outcomes — the
        // authoritative knob value matches the operator's intent. The
        // alternative (shortcircuit on first failure with no rollback)
        // leaves successfully-updated peers running ahead of the
        // snapshot, which is the worse drift.
        self.current_config = next_config;
        self.invalidate_stale_dynamic_max_prefix_restarts();

        if failures.is_empty() {
            info!(
                enabled,
                "hot-applied [global] honor_graceful_shutdown to EBGP peers"
            );
            Ok(())
        } else {
            Err(format!(
                "honor_graceful_shutdown applied with {} of {} EBGP peers failing \
                 (snapshot advanced anyway): {}",
                failures.len(),
                self.peers
                    .values()
                    .filter(|m| m.remote_asn != self.local_asn)
                    .count(),
                failures.join("; ")
            ))
        }
    }

    pub(super) async fn set_honor_blackhole(&mut self, enabled: bool) -> Result<(), String> {
        if self.current_config.global.honor_blackhole == enabled {
            return Ok(());
        }

        let mut next_config = self.current_config.clone();
        next_config.global.honor_blackhole = enabled;

        let targets: Vec<PeerKey> = self
            .peers
            .iter()
            .filter_map(|(peer, managed)| {
                (managed.remote_asn != self.local_asn).then_some(peer.clone())
            })
            .collect();

        let mut failures: Vec<String> = Vec::new();
        for peer_key in targets {
            let address = peer_key.address;
            let Some(managed) = self.peers.get(&peer_key) else {
                continue;
            };
            let neighbor = Self::policy_resolution_neighbor(&next_config, address, managed);
            let chains = next_config.effective_policy_chains_for_neighbor(&neighbor);
            let (import_policy, export_policy) = match chains {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        %address,
                        error = %e,
                        "honor_blackhole: failed to resolve effective chain — skipping peer"
                    );
                    failures.push(format!("{address}: chain-resolve: {e}"));
                    continue;
                }
            };
            if let Err(e) = self
                .update_runtime_policies_for_peer_key(
                    peer_key,
                    import_policy,
                    export_policy,
                    RefreshFailureHandling::Fatal,
                    None,
                )
                .await
            {
                warn!(
                    %address,
                    error = %e,
                    "honor_blackhole: failed to hot-apply on peer — desired snapshot \
                     advances anyway; bail-and-carry will retry on next policy edit"
                );
                failures.push(format!("{address}: hot-apply: {e}"));
            }
        }

        self.current_config = next_config;
        self.invalidate_stale_dynamic_max_prefix_restarts();

        if failures.is_empty() {
            info!(
                enabled,
                "hot-applied [global] honor_blackhole to EBGP peers"
            );
            Ok(())
        } else {
            Err(format!(
                "honor_blackhole applied with {} of {} EBGP peers failing \
                 (snapshot advanced anyway): {}",
                failures.len(),
                self.peers
                    .values()
                    .filter(|m| m.remote_asn != self.local_asn)
                    .count(),
                failures.join("; ")
            ))
        }
    }

    pub(super) fn peer_manager_config_from_resolved(
        resolved: crate::config::ResolvedNeighbor,
        gr_restart_eligible: bool,
    ) -> PeerManagerNeighborConfig {
        let tc = resolved.transport_config;
        PeerManagerNeighborConfig {
            address: tc.remote_addr.ip(),
            interface: tc.peer_interface.clone(),
            scope_id: tc.peer_scope_id,
            remote_asn: tc.peer.remote_asn,
            description: resolved.label,
            peer_group: resolved.peer_group,
            hold_time: Some(tc.peer.hold_time),
            send_hold_time: Some(tc.peer.send_hold_time),
            max_prefixes: tc.max_prefixes,
            max_prefixes_ipv4: tc.max_prefixes_ipv4,
            max_prefixes_ipv6: tc.max_prefixes_ipv6,
            max_prefix_restart_seconds: resolved.max_prefix_restart_seconds,
            md5_password: tc.md5_password.clone(),
            tcp_ao: tc.tcp_ao.clone(),
            ttl_security: tc.ttl_security,
            families: tc.peer.families.clone(),
            required_families: tc.peer.required_families.clone(),
            graceful_restart: tc.peer.graceful_restart,
            gr_restart_time: tc.peer.gr_restart_time,
            gr_peer_restart_time_max: tc.gr_peer_restart_time_max,
            gr_stale_routes_time: tc.gr_stale_routes_time,
            llgr_stale_time: tc.llgr_stale_time,
            gr_restart_eligible,
            local_ipv6_nexthop: tc.local_ipv6_nexthop,
            route_reflector_client: tc.route_reflector_client,
            orr_vantage: tc.orr_vantage,
            route_server_client: tc.route_server_client,
            per_client_best: tc.per_client_best,
            next_hop_ownership_strict_peer: tc.next_hop_ownership_strict_peer,
            slow_peer_threshold_pct: tc.slow_peer_threshold_pct,
            slow_peer_duration: tc.slow_peer_duration,
            slow_peer_isolation: tc.slow_peer_isolation,
            interpret_rfc1997: tc.interpret_rfc1997,
            rs_control_communities: tc.rs_control_communities,
            remove_private_as: tc.remove_private_as,
            add_path_receive: tc.peer.add_path_receive,
            add_path_send: tc.peer.add_path_send,
            add_path_send_max: tc.peer.add_path_send_max,
            paths_limit_receive_max: tc.peer.paths_limit_receive_max,
            local_role: tc.peer.local_role,
            strict_role: tc.peer.strict_role,
            prefix_orf_receive: tc.peer.prefix_orf_receive,
            disable_ipv4_unicast: tc.peer.disable_ipv4_unicast,
            import_policy: resolved.import_policy,
            export_policy: resolved.export_policy,
        }
    }

    pub(super) async fn apply_peer_group_change(
        &mut self,
        event: ConfigEvent,
        affected_peers: Vec<IpAddr>,
    ) -> Result<(), CatalogMutationError> {
        if let ConfigEvent::DeletePeerGroup { name, .. } = &event {
            let refs = peer_group_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(CatalogMutationError::StillReferenced {
                    kind: "peer group",
                    name: name.clone(),
                    references: refs,
                });
            }
        }

        let mut next_config = self.current_config.clone();
        apply_config_event(&mut next_config, &event).map_err(catalog_config_error)?;
        if next_config == self.current_config {
            return Ok(());
        }

        // ADR-0081: resolve every affected member's next config BEFORE
        // touching any peer, then commit the whole set through the
        // captured-prior reshape primitive. A resolution failure rejects with
        // zero peers touched; a mid-fanout reconfigure failure restores the
        // already-reshaped members from their captured priors instead of
        // leaving earlier members on the next config (and the failing member
        // possibly deleted) while `current_config` never advanced.
        let mut seen = BTreeSet::new();
        let mut targets: Vec<PeerManagerNeighborConfig> = Vec::new();
        for peer_key in affected_peers
            .into_iter()
            .flat_map(|address| self.peer_keys_for_address(address))
        {
            if !seen.insert(peer_key.clone()) {
                continue;
            }
            // A dynamic peer at an affected address is never reshaped here:
            // delete/re-add is wrong for an ephemeral accepted peer (ADR-0081
            // decision 4, and the primitive rejects dynamic targets). Its
            // running session keeps its config until it reconnects; resolved
            // policy chains hot-apply through the catalog policy fan-out.
            if self
                .peers
                .get(&peer_key)
                .is_some_and(|managed| managed.is_dynamic)
            {
                continue;
            }
            let address = peer_key.address;
            let Some(neighbor) = next_config.neighbors.iter().find(|neighbor| {
                neighbor.address == address.to_string() && neighbor.interface == peer_key.interface
            }) else {
                // Peer-group events never remove `[[neighbors]]` records, so
                // a static managed peer without one means the config snapshot
                // and the managed-peer set disagree. The old per-member loop
                // deleted the peer outright here; refuse instead (still zero
                // peers touched — this runs before the commit phase).
                return Err(CatalogMutationError::internal(format!(
                    "static peer {peer_key} affected by the peer-group change has no neighbor \
                     record in the updated config; refusing to reshape an inconsistent snapshot"
                )));
            };
            let resolved = next_config
                .resolve_neighbor(neighbor)
                .map_err(catalog_config_error)?;
            targets.push(Self::peer_manager_config_from_resolved(resolved, false));
        }

        let priors = self
            .apply_peer_reshape_snapshot(targets)
            .await
            .map_err(CatalogMutationError::from)?;

        self.current_config = next_config;
        if let ConfigEvent::SetPeerGroup { name, .. } = &event {
            self.sync_dynamic_max_prefix_restart_for_group(name);
        }
        self.invalidate_stale_dynamic_max_prefix_restarts();
        self.publish_policy_config_event(&event, priors.len());
        Ok(())
    }
}

#[cfg(test)]
mod first_poll_tests {
    use super::*;
    use tokio::sync::mpsc;

    #[derive(Debug, PartialEq, Eq)]
    enum QueueItem {
        Sentinel,
        Rollback,
        Marker,
    }

    #[tokio::test]
    async fn rollback_first_poll_registers_after_cooperative_budget_is_exhausted() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(QueueItem::Sentinel).await.unwrap();

        let rollback_tx = tx.clone();
        let mut rollback: PolicyRollbackRibFuture = Box::pin(async move {
            let result = rollback_tx
                .send(QueueItem::Rollback)
                .await
                .map_err(|_| RibCommandError::internal("test RIB channel unavailable"));
            (0, result)
        });
        let marker_tx = tx.clone();
        let mut marker = Box::pin(async move { marker_tx.send(QueueItem::Marker).await });

        std::future::poll_fn(|cx| {
            loop {
                match tokio::task::coop::poll_proceed(cx) {
                    Poll::Ready(permit) => permit.made_progress(),
                    Poll::Pending => return Poll::Ready(()),
                }
            }
        })
        .await;

        assert!(
            first_poll_policy_rollback_rib(&mut rollback)
                .await
                .is_none()
        );
        let marker_registered = std::future::poll_fn(|cx| {
            let mut marker = std::pin::pin!(tokio::task::unconstrained(marker.as_mut()));
            Poll::Ready(marker.as_mut().poll(cx).is_ready())
        })
        .await;
        assert!(!marker_registered);

        assert_eq!(
            tokio::task::unconstrained(rx.recv()).await,
            Some(QueueItem::Sentinel)
        );
        let readiness = std::future::poll_fn(|cx| {
            let marker_ready = {
                let mut marker = std::pin::pin!(tokio::task::unconstrained(marker.as_mut()));
                marker.as_mut().poll(cx).is_ready()
            };
            let rollback_ready = {
                let mut rollback = std::pin::pin!(tokio::task::unconstrained(rollback.as_mut()));
                rollback.as_mut().poll(cx).is_ready()
            };
            Poll::Ready((marker_ready, rollback_ready))
        })
        .await;

        // LOAD-BEARING: removing only the helper's `unconstrained` wrapper
        // changes this tuple to `(true, false)`: Marker claims the freed slot
        // because Rollback was never registered under the exhausted budget.
        assert_eq!(readiness, (false, true));
        assert_eq!(
            tokio::task::unconstrained(rx.recv()).await,
            Some(QueueItem::Rollback)
        );
    }
}
