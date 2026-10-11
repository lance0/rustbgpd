//! Committed source ownership and finite history accounting.
//!
//! Production keeps `history` absent. Test installation exercises these same
//! admission, received-chunk and recovery operations without enabling suppression.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroU64;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::dampening::{
    DampeningAdmission, DampeningCapacityNotice, DampeningCapacityReason, DampeningControlError,
    DampeningEnableReceipt, DampeningEngine, DampeningEvent, DampeningHistoryLimits, DampeningKey,
    DampeningOwner, DampeningParameters, DampeningSource,
};
use crate::update::{ReceivedRouteSource, WireRoutesReceived};

use super::RibManager;

#[derive(Default)]
pub(super) struct DampeningHistoryState {
    publication: Option<u64>,
    owners: HashMap<NonZeroU64, Arc<DampeningOwner>>,
    history: Option<HistoryStore>,
    retired_owners: BTreeMap<NonZeroU64, Arc<DampeningOwner>>,
    owner_retirement_cursor: Option<NonZeroU64>,
    owner_retirement_pending: bool,
    notices: Option<mpsc::UnboundedSender<DampeningCapacityNotice>>,
    notice_failed: bool,
}

struct HistoryStore {
    limits: DampeningHistoryLimits,
    parameters: DampeningParameters,
    sources: BTreeMap<DampeningSource, SourceHistory>,
    /// Includes each accepted enable's one-key reservation.
    keys: usize,
    next_recovery: u64,
    recovery: Option<DampeningEnableReceipt>,
    recovery_reserved_key: bool,
    recovery_reason: Option<DampeningCapacityReason>,
    started: tokio::time::Instant,
    retirement_pending: bool,
    retirement_cursor: Option<DampeningSource>,
}

struct SourceHistory {
    engine: DampeningEngine,
    admission: DampeningAdmission,
    blocked: Option<DampeningCapacityReason>,
}

impl DampeningHistoryState {
    pub(super) fn publish(
        &mut self,
        publication: u64,
        owners: Vec<Arc<DampeningOwner>>,
    ) -> Result<(), DampeningControlError> {
        let distinct: HashSet<_> = owners.iter().map(|owner| owner.id()).collect();
        if distinct.len() != owners.len() {
            return Err(DampeningControlError::StaleAuthority);
        }
        if self
            .history
            .as_ref()
            .is_some_and(|history| history.recovery.is_some())
        {
            return Err(DampeningControlError::RecoveryInProgress);
        }
        if let Some(previous) = self.publication {
            if previous > publication {
                return Err(DampeningControlError::StaleAuthority);
            }
            if previous == publication {
                return if owners.len() == self.owners.len()
                    && owners
                        .iter()
                        .all(|owner| self.owners.contains_key(&owner.id()))
                {
                    Ok(())
                } else {
                    Err(DampeningControlError::StaleAuthority)
                };
            }
        }
        let owners: HashMap<_, _> = owners
            .into_iter()
            .map(|owner| (owner.id(), owner))
            .collect();
        // Publication already visits the configured roster. Drop only small
        // owner records whose histories, sessions, notices and recovery latches
        // have physically disappeared; never destroy history in this step.
        self.retired_owners
            .retain(|_, owner| Arc::strong_count(owner) > 1);
        if let Some(history) = &self.history {
            let mut retained: HashSet<_> = owners.keys().copied().collect();
            retained.extend(self.owners.keys().copied());
            retained.extend(self.retired_owners.keys().copied());
            if retained.len() > history.limits.owners {
                return Err(DampeningControlError::OwnerCapacity);
            }
        }
        if owners.keys().any(|id| self.retired_owners.contains_key(id)) {
            return Err(DampeningControlError::StaleAuthority);
        }
        let mut newly_retired = false;
        for (id, owner) in &self.owners {
            if !owners.contains_key(id) {
                owner.set_records_wire_history(false);
                if self.history.is_some() {
                    self.retired_owners.insert(*id, Arc::clone(owner));
                    newly_retired = true;
                }
            }
        }
        self.arm_owner_retirement();
        for owner in owners.values() {
            owner.set_records_wire_history(self.history.is_some());
        }
        if newly_retired && let Some(history) = &mut self.history {
            history.retirement_pending = true;
            history.retirement_cursor = None;
        }
        self.owners = owners;
        self.publication = Some(publication);
        Ok(())
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub(super) fn install(
        &mut self,
        parameters: DampeningParameters,
        limits: DampeningHistoryLimits,
        notices: mpsc::UnboundedSender<DampeningCapacityNotice>,
    ) -> Result<(), DampeningControlError> {
        if [
            limits.owners,
            limits.sources,
            limits.history_keys,
            limits.source_history_keys,
        ]
        .contains(&0)
        {
            return Err(DampeningControlError::InvalidLimits);
        }
        if self.history.is_some() {
            return Err(DampeningControlError::RecoveryInProgress);
        }
        if self.owners.len() > limits.owners {
            return Err(DampeningControlError::OwnerCapacity);
        }
        self.notices = Some(notices);
        self.history = Some(HistoryStore {
            limits,
            parameters,
            sources: BTreeMap::new(),
            keys: 0,
            next_recovery: 1,
            recovery: None,
            recovery_reserved_key: false,
            recovery_reason: None,
            started: tokio::time::Instant::now(),
            retirement_pending: false,
            retirement_cursor: None,
        });
        for owner in self.owners.values() {
            owner.set_records_wire_history(true);
        }
        Ok(())
    }

    fn identity(source: &ReceivedRouteSource) -> Option<(DampeningSource, &DampeningAdmission)> {
        let context = source.context.as_ref()?;
        if context.route_server_client {
            return None;
        }
        let admission = context.dampening_admission.as_ref()?;
        Some((
            DampeningSource {
                owner: admission.owner.id(),
                peer: source.peer,
                peer_asn: source.peer_asn?,
            },
            admission,
        ))
    }

    /// Reserve before admitting reachable input. This return value is pinned
    /// in the pending batch; later publication cannot upgrade a tentative batch.
    fn admit(&mut self, source: &ReceivedRouteSource) -> Option<DampeningSource> {
        let history = self.history.as_mut()?;
        let (key, admission) = Self::identity(source)?;
        if !admission.is_published() || !self.owners.contains_key(&key.owner) {
            return None;
        }
        if let Some(retained) = history.sources.get(&key) {
            if let Some(reason) = retained.blocked {
                self.block(source, reason);
                return None;
            }
            return Some(key);
        }
        if history.sources.len() >= history.limits.sources {
            self.block(source, DampeningCapacityReason::Sources);
            return None;
        }
        history.sources.insert(
            key,
            SourceHistory {
                engine: DampeningEngine::new(history.parameters),
                admission: admission.clone(),
                blocked: None,
            },
        );
        Some(key)
    }

    fn block(&mut self, source: &ReceivedRouteSource, reason: DampeningCapacityReason) {
        let Some((key, admission)) = Self::identity(source) else {
            return;
        };
        let Some(history) = &mut self.history else {
            return;
        };
        let first = admission.block_once(key.peer_asn, reason);
        if let Some(retained) = history.sources.get_mut(&key) {
            retained.blocked = Some(reason);
            retained.admission.block_once(key.peer_asn, reason);
        }
        // The recovery latch already belongs to the managed peer. In
        // particular, source-credit exhaustion allocates no history tombstone.
        if first {
            let notice = DampeningCapacityNotice {
                source: source.clone(),
                reason,
            };
            self.notice_failed |= self
                .notices
                .as_ref()
                .is_none_or(|notices| notices.send(notice).is_err());
        }
    }

    pub(super) fn record(
        &mut self,
        source: &ReceivedRouteSource,
        admitted: DampeningSource,
        key: DampeningKey,
        event: DampeningEvent,
    ) {
        let Some(history) = &mut self.history else {
            return;
        };
        let Some(retained) = history.sources.get_mut(&admitted) else {
            return;
        };
        if retained.blocked.is_some() || !self.owners.contains_key(&admitted.owner) {
            return;
        }
        let now = history.started.elapsed();
        let existing = retained.engine.inspect(key, now).is_some();
        let reserved = history
            .recovery
            .is_some_and(|receipt| receipt.source == admitted)
            && history.recovery_reserved_key;
        if !existing && !matches!(event, DampeningEvent::Announcement) {
            let reason = if retained.engine.len() >= history.limits.source_history_keys {
                Some(DampeningCapacityReason::SourceHistoryKeys)
            } else if !reserved && history.keys >= history.limits.history_keys {
                Some(DampeningCapacityReason::HistoryKeys)
            } else {
                None
            };
            if let Some(reason) = reason {
                self.block(source, reason);
                return;
            }
        }
        let previous = retained.engine.len();
        retained.engine.record(key, event, now);
        let added = retained.engine.len() > previous;
        history.keys = history.keys - previous + retained.engine.len();
        if added && reserved {
            history.recovery_reserved_key = false;
            history.keys -= 1;
        }
    }

    pub(super) fn prepare_enable(
        &mut self,
        source: &ReceivedRouteSource,
        reason: DampeningCapacityReason,
    ) -> Result<DampeningEnableReceipt, DampeningControlError> {
        let (key, admission) =
            Self::identity(source).ok_or(DampeningControlError::StaleAuthority)?;
        if !self.owners.contains_key(&key.owner)
            || !admission.is_blocked()
            || !admission.capacity_disable_complete()
        {
            return Err(DampeningControlError::StaleAuthority);
        }
        let history = self
            .history
            .as_mut()
            .ok_or(DampeningControlError::StaleAuthority)?;
        if history.recovery.is_some() {
            return Err(DampeningControlError::RecoveryInProgress);
        }
        let created = !history.sources.contains_key(&key);
        if created && history.sources.len() >= history.limits.sources {
            return Err(DampeningControlError::Capacity(
                DampeningCapacityReason::Sources,
            ));
        }
        if history.keys >= history.limits.history_keys {
            return Err(DampeningControlError::Capacity(
                DampeningCapacityReason::HistoryKeys,
            ));
        }
        if history
            .sources
            .get(&key)
            .is_some_and(|retained| retained.engine.len() >= history.limits.source_history_keys)
        {
            return Err(DampeningControlError::Capacity(
                DampeningCapacityReason::SourceHistoryKeys,
            ));
        }
        let generation = history.next_recovery;
        history.next_recovery = generation
            .checked_add(1)
            .ok_or(DampeningControlError::IdentityExhausted)?;
        let retained = history.sources.entry(key).or_insert_with(|| SourceHistory {
            engine: DampeningEngine::new(history.parameters),
            admission: admission.clone(),
            blocked: Some(reason),
        });
        retained.admission = admission.clone();
        retained.blocked = None;
        // The PM caller has joined every old producer and fenced every exact
        // session on this primary lane while the managed peer remains disabled.
        // Reopen before Start so its first UPDATE cannot race a later unblock.
        admission.clear_blocked();
        history.keys += 1;
        let receipt = DampeningEnableReceipt {
            source: key,
            generation,
        };
        history.recovery = Some(receipt);
        history.recovery_reserved_key = true;
        history.recovery_reason = Some(reason);
        Ok(receipt)
    }

    pub(super) fn complete_enable(
        &mut self,
        receipt: DampeningEnableReceipt,
        enabled: bool,
    ) -> Result<(), DampeningControlError> {
        let history = self
            .history
            .as_mut()
            .ok_or(DampeningControlError::StaleAuthority)?;
        if history.recovery != Some(receipt) {
            return Err(DampeningControlError::StaleAuthority);
        }
        if enabled && !self.owners.contains_key(&receipt.source.owner) {
            return Err(DampeningControlError::StaleAuthority);
        }
        let retained = history
            .sources
            .get_mut(&receipt.source)
            .ok_or(DampeningControlError::StaleAuthority)?;
        if !enabled {
            let reason = history
                .recovery_reason
                .expect("accepted recovery retained its cause");
            retained.blocked.get_or_insert(reason);
            retained
                .admission
                .block_once(receipt.source.peer_asn, reason);
        }
        // Success must preserve a new exhaustion occurring after Prepare.
        // Failure keeps any newly allocated source/history charged and blocked.
        if history.recovery_reserved_key {
            history.keys -= 1;
        }
        history.recovery = None;
        history.recovery_reserved_key = false;
        history.recovery_reason = None;
        Ok(())
    }

    pub(super) fn arm_owner_retirement(&mut self) {
        if !self.retired_owners.is_empty() && !self.owner_retirement_pending {
            self.owner_retirement_pending = true;
            self.owner_retirement_cursor = None;
        }
    }

    pub(super) fn notice_failed(&self) -> bool {
        self.notice_failed
    }

    fn retire_owners(&mut self, budget: usize) -> usize {
        use std::ops::Bound::{Excluded, Unbounded};
        let mut processed = 0;
        while self.owner_retirement_pending && processed < budget {
            let lower = self.owner_retirement_cursor.map_or(Unbounded, Excluded);
            let Some((&id, owner)) = self.retired_owners.range((lower, Unbounded)).next() else {
                self.owner_retirement_pending = false;
                self.owner_retirement_cursor = None;
                break;
            };
            // History entries, queued batches/notices and managed recovery
            // targets all own the same Arc. Credit is released only after the
            // last physical consumer has gone, even for source-cap refusal.
            if Arc::strong_count(owner) == 1 {
                self.retired_owners.remove(&id);
            }
            self.owner_retirement_cursor = Some(id);
            processed += 1;
        }
        processed
    }

    /// Retired owners continue consuming credits until every node is removed.
    /// No current-source penalty is evicted to admit a different source.
    pub(super) fn retire(&mut self, budget: usize) -> usize {
        let Some(history) = &mut self.history else {
            return self.retire_owners(budget);
        };
        let mut processed = 0;
        while history.retirement_pending && processed < budget {
            use std::ops::Bound::{Excluded, Unbounded};
            let lower = history.retirement_cursor.map_or(Unbounded, Excluded);
            let Some((&key, _)) = history.sources.range((lower, Unbounded)).next() else {
                history.retirement_pending = false;
                history.retirement_cursor = None;
                break;
            };
            if self.owners.contains_key(&key.owner) {
                history.retirement_cursor = Some(key);
                processed += 1;
                continue;
            }
            let retained = history
                .sources
                .get_mut(&key)
                .expect("retiring source exists");
            let removed = retained.engine.retire(budget - processed).len();
            history.keys -= removed;
            // Empty and skipped sources are work too: no repeated full scan.
            processed += removed.max(1);
            if retained.engine.is_empty() {
                history.sources.remove(&key);
                history.retirement_cursor = Some(key);
            }
        }
        processed + self.retire_owners(budget - processed)
    }
}

impl RibManager {
    /// Retain the coalesced capacity-control lane without enabling history.
    #[must_use]
    pub fn with_dampening_capacity_notices(
        mut self,
        notices: mpsc::UnboundedSender<DampeningCapacityNotice>,
    ) -> Self {
        self.dampening_history.notices = Some(notices);
        self
    }

    pub(super) fn dampening_source_blocked(source: &ReceivedRouteSource) -> bool {
        source
            .context
            .as_ref()
            .and_then(|context| context.dampening_admission.as_ref())
            .is_some_and(DampeningAdmission::is_blocked)
    }

    pub(super) fn dampening_session_blocked(
        &self,
        peer: std::net::IpAddr,
        session_id: u64,
    ) -> bool {
        self.live_sessions
            .get(&peer)
            .and_then(|sessions| {
                sessions
                    .iter()
                    .find(|record| record.session_id == session_id)
            })
            .and_then(|record| record.source_context.as_ref())
            .and_then(|context| context.dampening_admission.as_ref())
            .is_some_and(DampeningAdmission::is_blocked)
    }

    /// Install explicit tiny budgets in cross-crate actor/transport tests.
    /// No runtime configuration path invokes this preparation seam.
    ///
    /// # Errors
    /// Rejects zero limits, an existing installation, or a committed roster
    /// larger than the explicitly supplied owner budget.
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn install_dampening_history_for_test(
        &mut self,
        parameters: DampeningParameters,
        limits: DampeningHistoryLimits,
        notices: mpsc::UnboundedSender<DampeningCapacityNotice>,
    ) -> Result<(), DampeningControlError> {
        self.dampening_history.install(parameters, limits, notices)
    }

    pub(super) fn admit_received_batch(&mut self, batch: WireRoutesReceived, original_wire: bool) {
        let WireRoutesReceived {
            peer,
            session_id,
            announced,
            withdrawn,
            original_unicast_withdrawals,
            flowspec_announced,
            flowspec_withdrawn,
            evpn_announced,
            evpn_withdrawn,
            validated_with,
        } = batch;
        if self.stale_session_message(
            peer,
            session_id,
            "RoutesReceived",
            rustbgpd_telemetry::metrics::StaleSessionMessageKind::Routes,
        ) {
            return;
        }
        let record = self.live_sessions.get(&peer).and_then(|sessions| {
            sessions
                .iter()
                .find(|record| record.session_id == session_id)
        });
        let source = ReceivedRouteSource {
            peer,
            session_id,
            peer_asn: record.map(|record| record.peer_asn),
            context: record.and_then(|record| record.source_context.clone()),
        };
        let qualified =
            record.is_some_and(|record| record.is_ebgp && !record.route_reflector_client);
        let admitted = (original_wire && qualified)
            .then(|| self.dampening_history.admit(&source))
            .flatten();
        // Even a capacity-refused source must apply this batch's withdrawals.
        // Reachable announcements are rejected at chunk processing instead.
        #[cfg(any(test, feature = "bench-internals"))]
        {
            self.adj_rib_out_commit_stats.routes_received_dispatches = self
                .adj_rib_out_commit_stats
                .routes_received_dispatches
                .saturating_add(1);
            self.adj_rib_out_commit_stats.routes_received_withdrawals = self
                .adj_rib_out_commit_stats
                .routes_received_withdrawals
                .saturating_add(withdrawn.len());
        }
        self.enqueue_routes_received(
            peer,
            announced,
            withdrawn,
            flowspec_announced,
            flowspec_withdrawn,
            evpn_announced,
            evpn_withdrawn,
            validated_with,
        );
        let pending = self
            .pending_route_batches
            .back_mut()
            .expect("received batch enqueued");
        pending.source = source;
        pending.dampening_source = admitted;
        pending.original_unicast_withdrawals = original_unicast_withdrawals;
    }

    pub(super) fn record_dampening_input(
        &mut self,
        source: &ReceivedRouteSource,
        admitted: Option<DampeningSource>,
        key: DampeningKey,
        event: DampeningEvent,
    ) {
        if let Some(admitted) = admitted {
            self.dampening_history.record(source, admitted, key, event);
        }
    }
}

#[cfg(test)]
mod tests;
