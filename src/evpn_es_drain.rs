//! ADR-0084 runtime Ethernet Segment drain — coordinator-side state
//! and the actor-facing drain primitive.
//!
//! The drained-ESI set is **runtime-only and in-memory**: a daemon
//! restart clears it and the actors replay configured state. The set
//! is owned here (one source of truth) and pushed to BOTH consumers on
//! every mutation:
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
//! `SetEthernetSegmentDrain` hook calls it today, and the planned
//! interface-bound automation trigger (ADR-0084 follow-on) reuses it
//! without going through the RPC layer.
//!
//! GC contract: when a runtime apply / SIGHUP replaces the segment set,
//! [`EvpnEsDrainState::retain_configured`] drops drain entries for
//! ESIs that left the config; entries for ESIs the config keeps
//! survive reloads.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use rustbgpd_wire::EthernetSegmentIdentifier;

use crate::evpn_originator::EvpnOriginatorRuntimeControl;
use crate::evpn_runtime_converger::evpn_vni_to_esi_map;
use crate::evpn_segment::EvpnSegmentRuntimeControl;

/// Shared, coordinator-owned drained-ESI set.
///
/// Mutations are serialized externally by the EVPN runtime apply lock
/// (the same `tokio::sync::Mutex` ADR-0063 applies and SIGHUP reloads
/// take), so the inner `std::sync::Mutex` only guards the pointer swap.
#[derive(Clone, Debug, Default)]
pub(crate) struct EvpnEsDrainState {
    inner: Arc<Mutex<Arc<BTreeSet<EthernetSegmentIdentifier>>>>,
}

impl EvpnEsDrainState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Arc<BTreeSet<EthernetSegmentIdentifier>>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Current drained-ESI snapshot.
    pub fn snapshot(&self) -> Arc<BTreeSet<EthernetSegmentIdentifier>> {
        self.lock().clone()
    }

    /// Set one ESI's drain state. Returns `Some((prior, new))` when the
    /// set changed, `None` for an idempotent no-op.
    #[allow(clippy::type_complexity)]
    pub fn set_drained(
        &self,
        esi: EthernetSegmentIdentifier,
        drained: bool,
    ) -> Option<(
        Arc<BTreeSet<EthernetSegmentIdentifier>>,
        Arc<BTreeSet<EthernetSegmentIdentifier>>,
    )> {
        let mut guard = self.lock();
        let prior = guard.clone();
        if drained == prior.contains(&esi) {
            return None;
        }
        let mut next = prior.as_ref().clone();
        if drained {
            next.insert(esi);
        } else {
            next.remove(&esi);
        }
        let next = Arc::new(next);
        *guard = next.clone();
        Some((prior, next))
    }

    /// Replace the whole set (used to roll back a failed publish).
    pub fn restore(&self, set: Arc<BTreeSet<EthernetSegmentIdentifier>>) {
        *self.lock() = set;
    }

    /// GC on segment-set replace: drop drain entries for ESIs that are
    /// no longer configured. Returns `Some(new)` when entries were
    /// dropped, `None` when nothing changed.
    pub fn retain_configured(
        &self,
        segments: &[rustbgpd_evpn::EthernetSegment],
    ) -> Option<Arc<BTreeSet<EthernetSegmentIdentifier>>> {
        let configured: BTreeSet<EthernetSegmentIdentifier> =
            segments.iter().map(|seg| seg.esi).collect();
        let mut guard = self.lock();
        if guard.iter().all(|esi| configured.contains(esi)) {
            return None;
        }
        let next: Arc<BTreeSet<EthernetSegmentIdentifier>> = Arc::new(
            guard
                .iter()
                .copied()
                .filter(|esi| configured.contains(esi))
                .collect(),
        );
        *guard = next.clone();
        Some(next)
    }
}

/// Result of applying a drain/undrain through the primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EsDrainOutcome {
    /// The applied state (mirrors the request for accepted calls).
    pub drained: bool,
    /// `false` when the request was an idempotent no-op.
    pub changed: bool,
    /// Member VNIs of the targeted ES in the committed config.
    pub member_vni_count: usize,
}

/// Error returned by the drain primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EsDrainError {
    /// The ESI is not in the committed Ethernet Segment config.
    UnknownEsi(String),
    /// An actor publish failed (actor exited / daemon tearing down).
    Unavailable(String),
}

/// Apply a drain/undrain for one configured Ethernet Segment.
///
/// Serialized against ADR-0063 runtime applies and SIGHUP reloads by
/// taking the shared EVPN runtime apply lock for the whole
/// validate → mutate → publish sequence, so the segment snapshot we
/// validate against cannot be swapped mid-flight.
pub(crate) async fn apply_ethernet_segment_drain(
    esi: EthernetSegmentIdentifier,
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

    let Some((prior, next)) = drain_state.set_drained(esi, drained) else {
        return Ok(EsDrainOutcome {
            drained,
            changed: false,
            member_vni_count,
        });
    };

    // Segment actor first: it owns the ES's own route classes. An ES
    // in the committed config implies the segment actor was spawned,
    // so a missing/closed control means teardown — fail without
    // mutating.
    let Some(segment) = segment else {
        drain_state.restore(prior);
        return Err(EsDrainError::Unavailable(
            "EVPN segment actor is not running".to_string(),
        ));
    };
    if !segment.replace_drained_esis(next.clone()) {
        drain_state.restore(prior);
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
            next.clone(),
        )
    {
        let _ = segment.replace_drained_esis(prior.clone());
        drain_state.restore(prior);
        return Err(EsDrainError::Unavailable(
            "EVPN Type 2 originator runtime control is closed".to_string(),
        ));
    }

    Ok(EsDrainOutcome {
        drained,
        changed: true,
        member_vni_count,
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

    #[test]
    fn set_drained_is_idempotent() {
        let state = EvpnEsDrainState::default();
        assert!(state.set_drained(esi(1), true).is_some());
        assert!(state.set_drained(esi(1), true).is_none(), "idempotent");
        assert!(state.snapshot().contains(&esi(1)));
        assert!(state.set_drained(esi(1), false).is_some());
        assert!(state.set_drained(esi(1), false).is_none(), "idempotent");
        assert!(state.snapshot().is_empty());
    }

    #[test]
    fn retain_configured_gcs_removed_esis_only() {
        let state = EvpnEsDrainState::default();
        let _ = state.set_drained(esi(1), true);
        let _ = state.set_drained(esi(2), true);

        // Both still configured — no change.
        assert!(
            state
                .retain_configured(&[segment(esi(1)), segment(esi(2))])
                .is_none()
        );

        // ESI 2 left the config — its drain entry is dropped, ESI 1's
        // survives the reload.
        let next = state
            .retain_configured(&[segment(esi(1))])
            .expect("entry dropped");
        assert!(next.contains(&esi(1)));
        assert!(!next.contains(&esi(2)));
        assert_eq!(state.snapshot().as_ref(), next.as_ref());
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
        let _ = drain_state.set_drained(esi(1), true);

        let outcome = apply_ethernet_segment_drain(
            esi(1),
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
    }
}
