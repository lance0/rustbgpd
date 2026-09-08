//! One owned SIGHUP runtime generation.
//!
//! The reload coordinator resolves a complete candidate once and hands it here
//! with one session action per static neighbor. The manager resolves the
//! final policy chains of every live peer against that same candidate and
//! applies the whole generation as one composed operation: the
//! rollback-capable policy snapshot first, then the config swap, in-place hot
//! updates, session replacements, removals, and additions. Every step captures
//! what restores it, so a determinate failure unwinds from retained in-memory
//! objects and never re-reads a file. A failed or unacknowledged unwind is
//! reported as ambiguous so the owner fences instead of claiming restoration.

use std::collections::BTreeMap;

use rustbgpd_api::peer_types::{
    ConfigEvent, OwnedHotUpdatePeerOutcome, PeerKey, PeerManagerNeighborConfig, ResolvedPeerPolicy,
};
use tracing::{error, info, warn};

use crate::config::{Config, ReloadPeerAction, ReloadPeerActionKind};
use crate::policy_admin;

use super::PeerManager;
use super::lifecycle::PeerReshapeSnapshotOutcome;
use super::policy::PolicySnapshotFailureKind;

/// Counts of the per-peer actions one generation applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReloadGenerationReceipt {
    pub(crate) policy_updated: usize,
    pub(crate) hot_updated: usize,
    pub(crate) replaced: usize,
    pub(crate) added: usize,
    pub(crate) removed: usize,
}

impl std::fmt::Display for ReloadGenerationReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy_updated={} hot_updated={} replaced={} added={} removed={}",
            self.policy_updated, self.hot_updated, self.replaced, self.added, self.removed
        )
    }
}

/// Actor-owned settlement proof for one reload generation.
#[derive(Debug)]
pub(crate) enum ReloadGenerationOutcome {
    /// Every action landed; the candidate is the manager's snapshot.
    Applied(ReloadGenerationReceipt),
    /// Rejected before any runtime effect.
    RejectedNoEffect(String),
    /// A step failed and every earlier effect was restored from retained priors.
    FullyCompensated(String),
    /// A forward or restoring effect left the runtime state unknown.
    CompensationAmbiguous(String),
}

/// Everything the generation resolved before touching a peer.
struct ResolvedGeneration {
    policy_targets: Vec<ResolvedPeerPolicy>,
    /// `(next, prior)` per hot-updated peer. The prior carries the candidate
    /// policies so restoring it touches knobs only; the policy snapshot owns
    /// policy restoration.
    hot: Vec<(PeerManagerNeighborConfig, PeerManagerNeighborConfig)>,
    replace: Vec<PeerManagerNeighborConfig>,
    remove: Vec<PeerKey>,
    add: Vec<PeerManagerNeighborConfig>,
}

/// A removed peer with the runtime state a faithful re-add needs.
struct RemovedPeer {
    config: PeerManagerNeighborConfig,
    enabled: bool,
    graceful_shutdown: bool,
}

/// Forward effects applied so far, each with what restores it.
#[derive(Default)]
struct AppliedEffects {
    policy_priors: Option<Vec<ResolvedPeerPolicy>>,
    prior_config: Option<Config>,
    hot_priors: Vec<PeerManagerNeighborConfig>,
    reshape_priors: Option<Vec<PeerManagerNeighborConfig>>,
    removed: Vec<RemovedPeer>,
    added: Vec<PeerKey>,
}

impl AppliedEffects {
    fn any(&self) -> bool {
        self.policy_priors.is_some()
            || self.prior_config.is_some()
            || !self.hot_priors.is_empty()
            || self.reshape_priors.is_some()
            || !self.removed.is_empty()
            || !self.added.is_empty()
    }
}

impl PeerManager {
    /// Apply `candidate` as one owned generation. `actions` is the session
    /// plan the coordinator derived from the prior and candidate configs.
    #[expect(
        clippy::too_many_lines,
        reason = "the generation keeps its six ordered phases and their failure classification in one auditable flow"
    )]
    pub(super) async fn apply_reload_generation(
        &mut self,
        candidate: Config,
        actions: Vec<ReloadPeerAction>,
    ) -> ReloadGenerationOutcome {
        let resolved = match self.resolve_reload_generation(&candidate, &actions) {
            Ok(resolved) => resolved,
            Err(error) => return ReloadGenerationOutcome::RejectedNoEffect(error),
        };
        let receipt = ReloadGenerationReceipt {
            policy_updated: resolved.policy_targets.len(),
            hot_updated: resolved.hot.len(),
            replaced: resolved.replace.len(),
            added: resolved.add.len(),
            removed: resolved.remove.len(),
        };
        info!(%receipt, "reload generation resolved; applying");
        let mut applied = AppliedEffects::default();

        // 1. Policy chains through the rollback-capable snapshot. No session
        //    identity is at stake yet, so a failure here costs nothing.
        match self
            .apply_resolved_policy_snapshot_classified(resolved.policy_targets, true)
            .await
        {
            Ok(priors) => applied.policy_priors = Some(priors),
            Err(failure) => {
                error!(
                    error = failure.code.as_str(),
                    reason = %failure.message,
                    "reload generation policy snapshot failed"
                );
                let message = format!("policy snapshot: {}", failure.message);
                return match failure.kind {
                    PolicySnapshotFailureKind::RejectedNoEffect => {
                        ReloadGenerationOutcome::RejectedNoEffect(message)
                    }
                    PolicySnapshotFailureKind::FullyCompensated => {
                        ReloadGenerationOutcome::FullyCompensated(message)
                    }
                    PolicySnapshotFailureKind::CompensationAmbiguous => {
                        ReloadGenerationOutcome::CompensationAmbiguous(message)
                    }
                };
            }
        }

        // 2. The candidate becomes the snapshot every later session
        //    construction reads (explain settings, registry, groups).
        applied.prior_config = Some(std::mem::replace(&mut self.current_config, candidate));

        // 3. Hot updates in place: knobs only, policies already match.
        for (next, prior) in resolved.hot {
            let peer = PeerKey::new(next.address, next.interface.clone());
            match self.hot_update_peer_owned(next).await {
                OwnedHotUpdatePeerOutcome::Success => applied.hot_priors.push(prior),
                OwnedHotUpdatePeerOutcome::RejectedNoEffect(error) => {
                    return self
                        .fail_reload_generation(
                            applied,
                            format!("hot update {peer}: {error}"),
                            false,
                        )
                        .await;
                }
                OwnedHotUpdatePeerOutcome::KnownDivergence(error) => {
                    return self
                        .fail_reload_generation(
                            applied,
                            format!("hot update {peer}: {error}"),
                            true,
                        )
                        .await;
                }
            }
        }

        // 4. Removals first, each captured with its admin and gshut state,
        //    so a later replacement or addition failure re-adds them.
        for peer in resolved.remove {
            let Some((enabled, graceful_shutdown)) = self
                .peers
                .get(&peer)
                .map(|managed| (managed.enabled, managed.advertise_graceful_shutdown))
            else {
                return self
                    .fail_reload_generation(
                        applied,
                        format!("remove {peer}: peer vanished before removal"),
                        false,
                    )
                    .await;
            };
            match self.delete_peer(peer.clone(), false).await {
                Ok(config) => applied.removed.push(RemovedPeer {
                    config,
                    enabled,
                    graceful_shutdown,
                }),
                Err(error) => {
                    return self
                        .fail_reload_generation(applied, format!("remove {peer}: {error}"), false)
                        .await;
                }
            }
        }

        // 5. Replacements: one delete/re-add per peer with final policies.
        //    The primitive restores its own already-reshaped members.
        if !resolved.replace.is_empty() {
            match self
                .apply_peer_reshape_snapshot_classified(
                    resolved.replace,
                    applied.prior_config.as_ref(),
                )
                .await
            {
                PeerReshapeSnapshotOutcome::Success(priors) => {
                    applied.reshape_priors = Some(priors);
                }
                PeerReshapeSnapshotOutcome::RejectedNoEffect(error)
                | PeerReshapeSnapshotOutcome::FullyCompensated(error) => {
                    return self
                        .fail_reload_generation(applied, format!("session replace: {error}"), false)
                        .await;
                }
                PeerReshapeSnapshotOutcome::CompensationAmbiguous(error) => {
                    return self
                        .fail_reload_generation(applied, format!("session replace: {error}"), true)
                        .await;
                }
            }
        }

        // 6. Additions.
        for config in resolved.add {
            let peer = PeerKey::new(config.address, config.interface.clone());
            if let Err(error) = self.add_peer(config, false).await {
                return self
                    .fail_reload_generation(applied, format!("add {peer}: {error}"), false)
                    .await;
            }
            applied.added.push(peer);
        }

        // 7. Post-commit bookkeeping the targeted catalog paths also perform.
        let prior_config = applied
            .prior_config
            .take()
            .expect("prior config retained for the whole generation");
        let mut changed_groups: Vec<(String, bool)> = self
            .current_config
            .peer_groups
            .iter()
            .filter(|(name, group)| prior_config.peer_groups.get(*name) != Some(group))
            .map(|(name, group)| {
                let purge = prior_config.peer_groups.get(name).is_some_and(|prior| {
                    crate::config::normalized_discard_path_attributes(
                        prior.discard_path_attributes.as_ref(),
                    ) != crate::config::normalized_discard_path_attributes(
                        group.discard_path_attributes.as_ref(),
                    )
                });
                (name.clone(), purge)
            })
            .collect();
        changed_groups.sort();
        for (name, purge) in &changed_groups {
            if *purge && let Err(error) = self.purge_dynamic_group_inheritors(name).await {
                return ReloadGenerationOutcome::CompensationAmbiguous(format!(
                    "purge dynamic inheritors of peer group {name:?}: {error}"
                ));
            }
            self.sync_dynamic_max_prefix_restart_for_group(name);
        }
        self.reconcile_stale_dynamic_max_prefix_restarts();
        self.metrics.record_policy_generation_loaded();
        self.publish_reload_generation_events(&prior_config, receipt.policy_updated);
        info!(%receipt, "reload generation applied");
        ReloadGenerationOutcome::Applied(receipt)
    }

    /// Resolve every action and policy target against `candidate` without
    /// touching a peer. Any inconsistency rejects the whole generation.
    #[expect(
        clippy::too_many_lines,
        reason = "action validation and per-peer chain resolution are one no-mutation preflight"
    )]
    fn resolve_reload_generation(
        &self,
        candidate: &Config,
        actions: &[ReloadPeerAction],
    ) -> Result<ResolvedGeneration, String> {
        candidate
            .validate_policy_chain_nodes()
            .map_err(|error| error.to_string())?;
        let mut kinds: BTreeMap<&PeerKey, ReloadPeerActionKind> = BTreeMap::new();
        for action in actions {
            if kinds.insert(&action.key, action.kind).is_some() {
                return Err(format!("peer {} has more than one action", action.key));
            }
        }
        let record = |peer: &PeerKey| {
            candidate.neighbors.iter().find(|neighbor| {
                neighbor.address == peer.address.to_string() && neighbor.interface == peer.interface
            })
        };
        let resolve = |peer: &PeerKey| -> Result<PeerManagerNeighborConfig, String> {
            let neighbor = record(peer)
                .ok_or_else(|| format!("peer {peer} has no neighbor record in the candidate"))?;
            let resolved = candidate
                .resolve_neighbor(neighbor)
                .map_err(|error| error.to_string())?;
            Ok(Self::peer_manager_config_from_resolved(resolved, false))
        };

        let mut resolved = ResolvedGeneration {
            policy_targets: Vec::new(),
            hot: Vec::new(),
            replace: Vec::new(),
            remove: Vec::new(),
            add: Vec::new(),
        };
        for (peer, kind) in &kinds {
            let managed = self.peers.get(peer);
            match kind {
                ReloadPeerActionKind::Add => {
                    if managed.is_some() {
                        return Err(format!("peer {peer} to add is already managed"));
                    }
                    resolved.add.push(resolve(peer)?);
                }
                ReloadPeerActionKind::Remove
                | ReloadPeerActionKind::Replace
                | ReloadPeerActionKind::HotUpdate => {
                    let managed = managed.ok_or_else(|| format!("peer {peer} is not managed"))?;
                    if managed.is_dynamic {
                        return Err(format!(
                            "peer {peer} is a dynamic peer; reload actions cover static neighbors only"
                        ));
                    }
                    match kind {
                        ReloadPeerActionKind::Remove => resolved.remove.push((*peer).clone()),
                        ReloadPeerActionKind::Replace => resolved.replace.push(resolve(peer)?),
                        ReloadPeerActionKind::HotUpdate => {
                            let next = resolve(peer)?;
                            let mut prior = Self::removed_peer_config(peer, managed);
                            prior.import_policy.clone_from(&next.import_policy);
                            prior.export_policy.clone_from(&next.export_policy);
                            resolved.hot.push((next, prior));
                        }
                        ReloadPeerActionKind::Add => unreachable!("matched above"),
                    }
                }
            }
        }

        // Final chains for every live peer that keeps its session, static and
        // dynamic. Replaced peers receive their chains on re-add.
        let mut live: Vec<&PeerKey> = self.peers.keys().collect();
        live.sort();
        for peer in live {
            if matches!(
                kinds.get(peer),
                Some(ReloadPeerActionKind::Replace | ReloadPeerActionKind::Remove)
            ) {
                continue;
            }
            let managed = &self.peers[peer];
            let neighbor = match record(peer) {
                Some(neighbor) => neighbor.clone(),
                None if managed.is_dynamic => {
                    Self::policy_resolution_neighbor(candidate, peer.address, managed)
                }
                None => {
                    return Err(format!(
                        "static peer {peer} has no neighbor record in the candidate and no removal action"
                    ));
                }
            };
            let chains = match candidate
                .effective_policy_for_neighbor(&neighbor, managed.rfc8212_external)
            {
                Ok(chains) => chains,
                Err(error @ crate::config::ConfigError::PolicyChainTooLarge { .. }) => {
                    return Err(error.to_string());
                }
                Err(error) if managed.is_dynamic => {
                    warn!(
                        %peer,
                        %error,
                        "reload generation: dynamic peer chains unresolvable; session keeps its prior chains"
                    );
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            if managed.import_policy == chains.import && managed.export_policy == chains.export {
                continue;
            }
            resolved.policy_targets.push(ResolvedPeerPolicy {
                address: peer.address,
                interface: peer.interface.clone(),
                import_policy: chains.import,
                export_policy: chains.export,
            });
        }
        Ok(resolved)
    }

    /// Classify a forward failure: unwind every retained prior unless the
    /// failing primitive already left state unknown.
    async fn fail_reload_generation(
        &mut self,
        applied: AppliedEffects,
        error: String,
        ambiguous: bool,
    ) -> ReloadGenerationOutcome {
        if ambiguous {
            return ReloadGenerationOutcome::CompensationAmbiguous(error);
        }
        if !applied.any() {
            return ReloadGenerationOutcome::RejectedNoEffect(error);
        }
        // Boxed: the unwind awaits every restoring primitive, and this future
        // is otherwise inlined at each failure site of the generation.
        match Box::pin(self.unwind_reload_generation(applied)).await {
            Ok(()) => ReloadGenerationOutcome::FullyCompensated(format!(
                "{error}; prior generation restored"
            )),
            Err(unwind) => ReloadGenerationOutcome::CompensationAmbiguous(format!(
                "{error}; restoring the prior generation failed: {unwind}"
            )),
        }
    }

    /// Restore retained priors in reverse application order. Every step is
    /// attempted; the aggregated error names each one that failed.
    async fn unwind_reload_generation(&mut self, applied: AppliedEffects) -> Result<(), String> {
        // Rebuilt peers resolve global transport settings from this snapshot.
        // Restore it before any re-add, including diagnostic retention knobs.
        if let Some(prior_config) = applied.prior_config {
            self.current_config = prior_config;
        }
        let mut failures = Vec::new();
        for peer in applied.added.into_iter().rev() {
            if let Err(error) = self.delete_peer(peer.clone(), false).await {
                failures.push(format!("delete added {peer}: {error}"));
            }
        }
        for removed in applied.removed.into_iter().rev() {
            let peer = PeerKey::new(removed.config.address, removed.config.interface.clone());
            if let Err(error) = self
                .add_peer_with_admin_state(removed.config, false, removed.enabled)
                .await
            {
                failures.push(format!("re-add removed {peer}: {error}"));
                continue;
            }
            if removed.graceful_shutdown
                && let Err(error) = self.set_graceful_shutdown(Some(peer.clone()), true).await
            {
                failures.push(format!("replay graceful shutdown on {peer}: {error}"));
            }
        }
        if let Some(priors) = applied.reshape_priors
            && let Err(error) = self.restore_peer_reshape_priors(priors, None).await
        {
            failures.push(error.to_string());
        }
        for prior in applied.hot_priors.into_iter().rev() {
            let peer = PeerKey::new(prior.address, prior.interface.clone());
            if let Err(error) = self.hot_update_peer_in_place(prior).await {
                failures.push(format!("restore hot update {peer}: {error}"));
            }
        }
        if let Some(priors) = applied.policy_priors
            && let Err(error) = self.apply_resolved_policy_snapshot(priors).await
        {
            failures.push(format!("restore policy chains: {error}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    /// Publish the same catalog events the targeted mutation paths publish,
    /// one per changed definition, so event consumers see one reload
    /// generation as the mutations it contains.
    fn publish_reload_generation_events(&mut self, prior: &Config, affected_peers: usize) {
        let next = self.current_config.clone();
        let policy = crate::config::diff_policy(&prior.policy, &next.policy);
        let groups = crate::config::diff_peer_groups(&prior.peer_groups, &next.peer_groups);
        let mut events = Vec::new();
        for name in policy
            .neighbor_sets_added
            .iter()
            .chain(&policy.neighbor_sets_changed)
        {
            if let Some(definition) = policy_admin::named_neighbor_set_from_config(&next, name) {
                events.push(ConfigEvent::SetNeighborSet {
                    name: name.clone(),
                    definition,
                    ack: None,
                });
            }
        }
        for name in policy
            .definitions_added
            .iter()
            .chain(&policy.definitions_changed)
        {
            if let Some(definition) = policy_admin::named_policy_from_config(&next, name) {
                events.push(ConfigEvent::SetPolicy {
                    name: name.clone(),
                    definition,
                    ack: None,
                });
            }
        }
        for name in groups.added.iter().chain(&groups.changed) {
            if let Some(definition) = policy_admin::named_peer_group_from_config(&next, name) {
                events.push(ConfigEvent::SetPeerGroup {
                    name: name.clone(),
                    definition,
                    ack: None,
                });
            }
        }
        if policy.import_chain_changed {
            events.push(if next.policy.import_chain.is_empty() {
                ConfigEvent::ClearGlobalImportChain { ack: None }
            } else {
                ConfigEvent::SetGlobalImportChain {
                    policy_names: next.policy.import_chain.clone(),
                    ack: None,
                }
            });
        }
        if policy.export_chain_changed {
            events.push(if next.policy.export_chain.is_empty() {
                ConfigEvent::ClearGlobalExportChain { ack: None }
            } else {
                ConfigEvent::SetGlobalExportChain {
                    policy_names: next.policy.export_chain.clone(),
                    ack: None,
                }
            });
        }
        for name in &groups.removed {
            events.push(ConfigEvent::DeletePeerGroup {
                name: name.clone(),
                ack: None,
            });
        }
        for name in &policy.definitions_removed {
            events.push(ConfigEvent::DeletePolicy {
                name: name.clone(),
                ack: None,
            });
        }
        for name in &policy.neighbor_sets_removed {
            events.push(ConfigEvent::DeleteNeighborSet {
                name: name.clone(),
                ack: None,
            });
        }
        for event in &events {
            self.publish_policy_config_event(event, affected_peers);
        }
    }
}
