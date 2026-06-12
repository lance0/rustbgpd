//! ADR-0084 runtime Ethernet Segment drain — coordinator-side state
//! and the actor-facing drain primitive.
//!
//! The drained set is **runtime-only and in-memory**: a daemon restart
//! clears it and the actors replay configured state (bound segments
//! self-correct: the ADR-0085 link coordinator re-reads carrier at
//! startup and re-drains a dead AC). Since ADR-0085 decision 2 the set
//! is **reason-keyed**: `ESI → {Operator, Link}`. An ES is drained
//! while its reason set is non-empty — an operator undrain does not
//! override a dead link, and link recovery does not override an
//! operator drain. Reasons live only here in the coordinator; both
//! actor consumers keep receiving the FLAT drained-ESI set:
//!
//! - the segment actor (`src/evpn_segment.rs`) via its drained-ESI
//!   watch — withdraws/re-originates the ES's Type 4 + EAD routes and
//!   keeps the ES suppressed across snapshot reapplication;
//! - the Type 2 originator (`src/evpn_originator`) via its runtime
//!   model — withdraws local MAC/MAC+IP routes for member VNIs without
//!   clearing observation caches (drain-without-replay) and suppresses
//!   fresh kernel-event originations while drained.
//!
//! [`apply_ethernet_segment_drain`] is the shared primitive: the gRPC
//! `SetEthernetSegmentDrain` hook adds/removes the `Operator` reason,
//! and the ADR-0085 link coordinator (`src/evpn_es_link_drain.rs`)
//! adds/removes the `Link` reason, both through the same call.
//!
//! GC contract: when a runtime apply / SIGHUP replaces the segment set,
//! [`EvpnEsDrainState::retain_configured`] drops drain entries — ALL
//! reasons — for ESIs that left the config; entries for ESIs the
//! config keeps survive reloads.
//!
//! Observability: every committed mutation syncs the
//! `evpn_es_drained{esi, reason}` gauge when the state was built with
//! [`EvpnEsDrainState::with_metrics`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::EthernetSegmentIdentifier;

use crate::evpn_originator::EvpnOriginatorRuntimeControl;
use crate::evpn_runtime_converger::evpn_vni_to_esi_map;
use crate::evpn_segment::EvpnSegmentRuntimeControl;

/// Why an Ethernet Segment is drained (ADR-0085 decision 2). The
/// reasons compose: the ES is drained while ANY reason is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EsDrainReason {
    /// `SetEthernetSegmentDrain` RPC (ADR-0084).
    Operator,
    /// Attachment-circuit carrier via the `interface` binding
    /// (ADR-0085 decisions 1 + 3).
    Link,
}

impl EsDrainReason {
    /// Every reason, in the stable order used for metrics cleanup and
    /// response rendering.
    pub const ALL: [EsDrainReason; 2] = [EsDrainReason::Operator, EsDrainReason::Link];

    /// Lowercase label used on the wire (RPC `reasons` field) and as
    /// the `reason` label of the `evpn_es_drained` gauge.
    pub fn as_str(self) -> &'static str {
        match self {
            EsDrainReason::Operator => "operator",
            EsDrainReason::Link => "link",
        }
    }
}

impl std::fmt::Display for EsDrainReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reason-keyed drained map. ESIs with an empty reason set are not
/// present (the flat projection is exactly the key set).
pub(crate) type EsDrainReasonMap = BTreeMap<EthernetSegmentIdentifier, BTreeSet<EsDrainReason>>;

/// The two synchronized projections of the drained state: the
/// reason-keyed source of truth and the derived flat set the actors
/// consume.
#[derive(Debug, Default)]
struct DrainSets {
    reasons: Arc<EsDrainReasonMap>,
    flat: Arc<BTreeSet<EthernetSegmentIdentifier>>,
}

/// Shared, coordinator-owned drained-ESI state.
///
/// Mutations are serialized externally by the EVPN runtime apply lock
/// (the same `tokio::sync::Mutex` ADR-0063 applies and SIGHUP reloads
/// take), so the inner `std::sync::Mutex` only guards the pointer swap.
#[derive(Clone, Debug, Default)]
pub(crate) struct EvpnEsDrainState {
    inner: Arc<Mutex<DrainSets>>,
    /// `evpn_es_drained{esi, reason}` gauge sink; `None` in tests that
    /// only exercise the state machine.
    metrics: Option<BgpMetrics>,
}

/// Committed `set_reason` mutation: rollback token plus the actor
/// fanout payloads.
#[derive(Debug)]
pub(crate) struct EsDrainTransition {
    /// Reason map before the mutation — the rollback token for
    /// [`EvpnEsDrainState::restore`].
    pub prior_reasons: Arc<EsDrainReasonMap>,
    /// Flat set before the mutation (segment-actor rollback payload).
    pub prior_flat: Arc<BTreeSet<EthernetSegmentIdentifier>>,
    /// Flat set after the mutation (actor fanout payload). Equal to
    /// `prior_flat` when the mutation changed only the reason
    /// composition, not the composed drained state.
    pub next_flat: Arc<BTreeSet<EthernetSegmentIdentifier>>,
    /// The mutated ESI's reason set after the mutation.
    pub reasons_after: BTreeSet<EsDrainReason>,
}

fn flat_of(reasons: &EsDrainReasonMap) -> Arc<BTreeSet<EthernetSegmentIdentifier>> {
    Arc::new(reasons.keys().copied().collect())
}

impl EvpnEsDrainState {
    /// State that mirrors every committed mutation into the
    /// `evpn_es_drained{esi, reason}` gauge.
    pub fn with_metrics(metrics: BgpMetrics) -> Self {
        Self {
            inner: Arc::default(),
            metrics: Some(metrics),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DrainSets> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Sync the gauge for every `(esi, reason)` whose membership
    /// differs between `prior` and `next`.
    fn sync_metrics(&self, prior: &EsDrainReasonMap, next: &EsDrainReasonMap) {
        let Some(metrics) = self.metrics.as_ref() else {
            return;
        };
        let empty = BTreeSet::new();
        let esis: BTreeSet<&EthernetSegmentIdentifier> = prior.keys().chain(next.keys()).collect();
        for esi in esis {
            let before = prior.get(esi).unwrap_or(&empty);
            let after = next.get(esi).unwrap_or(&empty);
            for reason in EsDrainReason::ALL {
                let held = after.contains(&reason);
                if before.contains(&reason) != held {
                    metrics.set_evpn_es_drained(&esi.to_string(), reason.as_str(), held);
                }
            }
        }
    }

    /// Current flat drained-ESI snapshot (the actor fanout shape).
    pub fn snapshot(&self) -> Arc<BTreeSet<EthernetSegmentIdentifier>> {
        self.lock().flat.clone()
    }

    /// One ESI's current reason set (empty when not drained).
    pub fn reasons_for(&self, esi: EthernetSegmentIdentifier) -> BTreeSet<EsDrainReason> {
        self.lock().reasons.get(&esi).cloned().unwrap_or_default()
    }

    /// Add or remove one drain reason for one ESI. Returns `None` for
    /// an idempotent no-op (the reason already matched `held`).
    pub fn set_reason(
        &self,
        esi: EthernetSegmentIdentifier,
        reason: EsDrainReason,
        held: bool,
    ) -> Option<EsDrainTransition> {
        let mut guard = self.lock();
        let prior_reasons = guard.reasons.clone();
        let currently_held = prior_reasons
            .get(&esi)
            .is_some_and(|set| set.contains(&reason));
        if held == currently_held {
            return None;
        }
        let mut next = prior_reasons.as_ref().clone();
        let mut reasons_after = next.remove(&esi).unwrap_or_default();
        if held {
            reasons_after.insert(reason);
        } else {
            reasons_after.remove(&reason);
        }
        if !reasons_after.is_empty() {
            next.insert(esi, reasons_after.clone());
        }
        let next = Arc::new(next);
        let prior_flat = guard.flat.clone();
        let next_flat = if next.contains_key(&esi) == prior_flat.contains(&esi) {
            prior_flat.clone()
        } else {
            flat_of(&next)
        };
        guard.reasons = next.clone();
        guard.flat = next_flat.clone();
        drop(guard);
        self.sync_metrics(&prior_reasons, &next);
        Some(EsDrainTransition {
            prior_reasons,
            prior_flat,
            next_flat,
            reasons_after,
        })
    }

    /// Replace the whole reason map (used to roll back a failed
    /// publish). The flat projection and the gauge follow.
    pub fn restore(&self, reasons: Arc<EsDrainReasonMap>) {
        let mut guard = self.lock();
        guard.flat = flat_of(&reasons);
        let prior = std::mem::replace(&mut guard.reasons, reasons);
        let next = guard.reasons.clone();
        drop(guard);
        self.sync_metrics(&prior, &next);
    }

    /// GC on segment-set replace: drop drain entries — all reasons —
    /// for ESIs that are no longer configured (their gauge series are
    /// removed too). Returns `Some(new_flat)` when entries were
    /// dropped, `None` when nothing changed.
    pub fn retain_configured(
        &self,
        segments: &[rustbgpd_evpn::EthernetSegment],
    ) -> Option<Arc<BTreeSet<EthernetSegmentIdentifier>>> {
        let configured: BTreeSet<EthernetSegmentIdentifier> =
            segments.iter().map(|seg| seg.esi).collect();
        let mut guard = self.lock();
        if guard.reasons.keys().all(|esi| configured.contains(esi)) {
            return None;
        }
        let prior = guard.reasons.clone();
        let next: EsDrainReasonMap = prior
            .iter()
            .filter(|(esi, _)| configured.contains(*esi))
            .map(|(esi, reasons)| (*esi, reasons.clone()))
            .collect();
        let next_flat = flat_of(&next);
        guard.reasons = Arc::new(next);
        guard.flat = next_flat.clone();
        drop(guard);
        if let Some(metrics) = self.metrics.as_ref() {
            for esi in prior.keys().filter(|esi| !configured.contains(esi)) {
                metrics.remove_evpn_es_drained(
                    &esi.to_string(),
                    &EsDrainReason::ALL.map(EsDrainReason::as_str),
                );
            }
        }
        Some(next_flat)
    }
}

/// Result of applying a drain/undrain through the primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EsDrainOutcome {
    /// Composed drain state after the request: `true` while ANY reason
    /// is held (may differ from the request — an operator undrain
    /// against a link-drained ES leaves the ES drained).
    pub drained: bool,
    /// `false` when the request was an idempotent no-op for the
    /// requested reason.
    pub changed: bool,
    /// Member VNIs of the targeted ES in the committed config.
    pub member_vni_count: usize,
    /// The ESI's reason set after the request.
    pub reasons: BTreeSet<EsDrainReason>,
}

/// Error returned by the drain primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EsDrainError {
    /// The ESI is not in the committed Ethernet Segment config.
    UnknownEsi(String),
    /// An actor publish failed (actor exited / daemon tearing down).
    Unavailable(String),
}

/// Apply a drain/undrain of one reason for one configured Ethernet
/// Segment.
///
/// Serialized against ADR-0063 runtime applies and SIGHUP reloads by
/// taking the shared EVPN runtime apply lock for the whole
/// validate → mutate → publish sequence, so the segment snapshot we
/// validate against cannot be swapped mid-flight.
///
/// Actor fanout only happens when the COMPOSED drained set changed; a
/// mutation that only recomposed the reason set (e.g. a link failure
/// on an already operator-drained ES) commits coordinator-side with
/// no actor traffic — the routes are already withdrawn.
#[allow(clippy::too_many_arguments)] // the drain dependency spine, mirrored from the ADR-0084 hook
pub(crate) async fn apply_ethernet_segment_drain(
    esi: EthernetSegmentIdentifier,
    reason: EsDrainReason,
    drained: bool,
    apply_lock: &tokio::sync::Mutex<()>,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    drain_state: &EvpnEsDrainState,
    segment: Option<&EvpnSegmentRuntimeControl>,
    originator: Option<&EvpnOriginatorRuntimeControl>,
) -> Result<EsDrainOutcome, EsDrainError> {
    let _guard = apply_lock.lock().await;

    // Validate against the committed model: drain targets only
    // configured ESIs.
    let (instances, segments) = {
        let model = match coordinator.lock() {
            Ok(guard) => guard.model().clone(),
            Err(poisoned) => poisoned.into_inner().model().clone(),
        };
        (
            Arc::new(model.instances().clone()),
            model.ethernet_segments().to_vec(),
        )
    };
    let Some(target) = segments.iter().find(|seg| seg.esi == esi) else {
        return Err(EsDrainError::UnknownEsi(format!(
            "Ethernet Segment {esi} is not configured"
        )));
    };
    let member_vni_count = target.member_vnis.len();

    let Some(transition) = drain_state.set_reason(esi, reason, drained) else {
        let reasons = drain_state.reasons_for(esi);
        return Ok(EsDrainOutcome {
            drained: !reasons.is_empty(),
            changed: false,
            member_vni_count,
            reasons,
        });
    };

    // Reason recomposition without a composed-state change: the actors
    // already hold the right flat set — nothing to publish.
    if Arc::ptr_eq(&transition.prior_flat, &transition.next_flat) {
        return Ok(EsDrainOutcome {
            drained: !transition.reasons_after.is_empty(),
            changed: true,
            member_vni_count,
            reasons: transition.reasons_after,
        });
    }

    // Segment actor first: it owns the ES's own route classes. An ES
    // in the committed config implies the segment actor was spawned,
    // so a missing/closed control means teardown — fail without
    // mutating.
    let Some(segment) = segment else {
        drain_state.restore(transition.prior_reasons);
        return Err(EsDrainError::Unavailable(
            "EVPN segment actor is not running".to_string(),
        ));
    };
    if !segment.replace_drained_esis(transition.next_flat.clone()) {
        drain_state.restore(transition.prior_reasons);
        return Err(EsDrainError::Unavailable(
            "EVPN segment runtime control is closed".to_string(),
        ));
    }

    // Type 2 originator second: withdraw/replay local MAC state for
    // the member VNIs. Absent on RR-only deployments (no local MACs to
    // drain). On failure roll the segment actor and the shared set
    // back so both consumers stay consistent.
    if let Some(originator) = originator
        && !originator.replace_runtime_model(
            instances,
            evpn_vni_to_esi_map(&segments),
            transition.next_flat.clone(),
        )
    {
        let _ = segment.replace_drained_esis(transition.prior_flat.clone());
        drain_state.restore(transition.prior_reasons);
        return Err(EsDrainError::Unavailable(
            "EVPN Type 2 originator runtime control is closed".to_string(),
        ));
    }

    Ok(EsDrainOutcome {
        drained: !transition.reasons_after.is_empty(),
        changed: true,
        member_vni_count,
        reasons: transition.reasons_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn segment(id: EthernetSegmentIdentifier) -> rustbgpd_evpn::EthernetSegment {
        rustbgpd_evpn::EthernetSegment {
            esi: id,
            member_vnis: std::collections::BTreeSet::new(),
            df_preference: 32_768,
            df_algorithm: rustbgpd_evpn::DfAlgorithm::DefaultModulo,
            df_dont_preempt: false,
            redundancy_mode: rustbgpd_evpn::RedundancyMode::AllActive,
            originator_ip: "10.0.0.1".parse().unwrap(),
        }
    }

    fn reasons(list: &[EsDrainReason]) -> BTreeSet<EsDrainReason> {
        list.iter().copied().collect()
    }

    #[test]
    fn set_reason_is_idempotent_per_reason() {
        let state = EvpnEsDrainState::default();
        assert!(
            state
                .set_reason(esi(1), EsDrainReason::Operator, true)
                .is_some()
        );
        assert!(
            state
                .set_reason(esi(1), EsDrainReason::Operator, true)
                .is_none(),
            "idempotent add"
        );
        assert!(state.snapshot().contains(&esi(1)));
        assert!(
            state
                .set_reason(esi(1), EsDrainReason::Operator, false)
                .is_some()
        );
        assert!(
            state
                .set_reason(esi(1), EsDrainReason::Operator, false)
                .is_none(),
            "idempotent remove"
        );
        assert!(state.snapshot().is_empty());
        assert!(state.reasons_for(esi(1)).is_empty());
    }

    /// The ADR-0085 maintenance flow: operator drain → link flap
    /// changes nothing composed → operator undrain while the link is
    /// down stays drained → link recovery finally undrains.
    #[test]
    fn operator_and_link_reasons_compose_independently() {
        let state = EvpnEsDrainState::default();

        // Operator drains for maintenance.
        let t = state
            .set_reason(esi(1), EsDrainReason::Operator, true)
            .expect("operator drain");
        assert!(t.next_flat.contains(&esi(1)));

        // Cable work: link goes down. Reason recorded, composed flat
        // set unchanged (already drained) — same Arc, no fanout needed.
        let t = state
            .set_reason(esi(1), EsDrainReason::Link, true)
            .expect("link drain");
        assert!(Arc::ptr_eq(&t.prior_flat, &t.next_flat));
        assert_eq!(
            t.reasons_after,
            reasons(&[EsDrainReason::Operator, EsDrainReason::Link])
        );

        // Link flaps back up mid-maintenance (recovery elapsed):
        // composed state still drained by the operator.
        let t = state
            .set_reason(esi(1), EsDrainReason::Link, false)
            .expect("link recovery");
        assert!(t.next_flat.contains(&esi(1)));
        let t = state
            .set_reason(esi(1), EsDrainReason::Link, true)
            .expect("link down again");
        assert!(t.next_flat.contains(&esi(1)));

        // Operator undrains while the link is still down: the ES MUST
        // stay drained (link reason holds).
        let t = state
            .set_reason(esi(1), EsDrainReason::Operator, false)
            .expect("operator undrain");
        assert!(Arc::ptr_eq(&t.prior_flat, &t.next_flat));
        assert!(t.next_flat.contains(&esi(1)));
        assert_eq!(t.reasons_after, reasons(&[EsDrainReason::Link]));

        // Link recovers: last reason drops, ES undrains.
        let t = state
            .set_reason(esi(1), EsDrainReason::Link, false)
            .expect("final recovery");
        assert!(t.next_flat.is_empty());
        assert!(t.reasons_after.is_empty());
    }

    #[test]
    fn restore_rolls_back_reasons_and_flat_projection() {
        let state = EvpnEsDrainState::default();
        let _ = state.set_reason(esi(1), EsDrainReason::Link, true);
        let t = state
            .set_reason(esi(2), EsDrainReason::Operator, true)
            .expect("second drain");

        state.restore(t.prior_reasons);
        assert!(state.snapshot().contains(&esi(1)));
        assert!(!state.snapshot().contains(&esi(2)));
        assert_eq!(state.reasons_for(esi(1)), reasons(&[EsDrainReason::Link]));
        assert!(state.reasons_for(esi(2)).is_empty());
    }

    #[test]
    fn retain_configured_gcs_removed_esis_only_and_drops_all_reasons() {
        let state = EvpnEsDrainState::default();
        let _ = state.set_reason(esi(1), EsDrainReason::Operator, true);
        let _ = state.set_reason(esi(2), EsDrainReason::Operator, true);
        let _ = state.set_reason(esi(2), EsDrainReason::Link, true);

        // Both still configured — no change.
        assert!(
            state
                .retain_configured(&[segment(esi(1)), segment(esi(2))])
                .is_none()
        );

        // ESI 2 left the config — its entry (both reasons) is dropped,
        // ESI 1's survives the reload.
        let next = state
            .retain_configured(&[segment(esi(1))])
            .expect("entry dropped");
        assert!(next.contains(&esi(1)));
        assert!(!next.contains(&esi(2)));
        assert_eq!(state.snapshot().as_ref(), next.as_ref());
        assert!(state.reasons_for(esi(2)).is_empty(), "GC drops all reasons");
        assert_eq!(
            state.reasons_for(esi(1)),
            reasons(&[EsDrainReason::Operator])
        );
    }

    #[tokio::test]
    async fn drain_rejects_unconfigured_esi() {
        let apply_lock = tokio::sync::Mutex::new(());
        let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            Arc::new(rustbgpd_evpn::EvpnInstanceTable::new()),
            Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
            vec![segment(esi(1))],
        ));
        let drain_state = EvpnEsDrainState::default();

        let err = apply_ethernet_segment_drain(
            esi(9),
            EsDrainReason::Operator,
            true,
            &apply_lock,
            &coordinator,
            &drain_state,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, EsDrainError::UnknownEsi(_)));
        assert!(drain_state.snapshot().is_empty(), "no mutation on reject");
    }

    #[tokio::test]
    async fn drain_without_segment_actor_fails_without_mutating() {
        let apply_lock = tokio::sync::Mutex::new(());
        let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            Arc::new(rustbgpd_evpn::EvpnInstanceTable::new()),
            Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
            vec![segment(esi(1))],
        ));
        let drain_state = EvpnEsDrainState::default();

        let err = apply_ethernet_segment_drain(
            esi(1),
            EsDrainReason::Operator,
            true,
            &apply_lock,
            &coordinator,
            &drain_state,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, EsDrainError::Unavailable(_)));
        assert!(
            drain_state.snapshot().is_empty(),
            "failed publish must roll the in-memory set back"
        );
        assert!(
            drain_state.reasons_for(esi(1)).is_empty(),
            "failed publish must roll the reason map back"
        );
    }

    #[tokio::test]
    async fn drain_is_idempotent_through_the_primitive() {
        let apply_lock = tokio::sync::Mutex::new(());
        let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            Arc::new(rustbgpd_evpn::EvpnInstanceTable::new()),
            Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
            vec![segment(esi(1))],
        ));
        let drain_state = EvpnEsDrainState::default();
        // Pre-drained set; a second drain request must be a no-op that
        // never touches the (absent) actor controls.
        let _ = drain_state.set_reason(esi(1), EsDrainReason::Operator, true);

        let outcome = apply_ethernet_segment_drain(
            esi(1),
            EsDrainReason::Operator,
            true,
            &apply_lock,
            &coordinator,
            &drain_state,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(outcome.drained);
        assert!(!outcome.changed);
        assert_eq!(outcome.reasons, reasons(&[EsDrainReason::Operator]));
    }

    /// A reason recomposition without a composed-state change must
    /// commit without touching the actors — exercised here by passing
    /// NO actor controls: if the primitive tried to fan out, it would
    /// fail Unavailable.
    #[tokio::test]
    async fn reason_recomposition_skips_actor_fanout() {
        let apply_lock = tokio::sync::Mutex::new(());
        let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            Arc::new(rustbgpd_evpn::EvpnInstanceTable::new()),
            Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
            vec![segment(esi(1))],
        ));
        let drain_state = EvpnEsDrainState::default();
        let _ = drain_state.set_reason(esi(1), EsDrainReason::Operator, true);

        // Link reason lands on the already-drained ES: composed state
        // unchanged → no fanout → success even with no actors.
        let outcome = apply_ethernet_segment_drain(
            esi(1),
            EsDrainReason::Link,
            true,
            &apply_lock,
            &coordinator,
            &drain_state,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(outcome.drained);
        assert!(outcome.changed);
        assert_eq!(
            outcome.reasons,
            reasons(&[EsDrainReason::Operator, EsDrainReason::Link])
        );

        // Operator undrain while the link reason holds: still no
        // composed change, still no fanout, ES reports drained.
        let outcome = apply_ethernet_segment_drain(
            esi(1),
            EsDrainReason::Operator,
            false,
            &apply_lock,
            &coordinator,
            &drain_state,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(outcome.drained, "link reason keeps the ES drained");
        assert!(outcome.changed);
        assert_eq!(outcome.reasons, reasons(&[EsDrainReason::Link]));
    }
}
