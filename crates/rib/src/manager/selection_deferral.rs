//! RFC 4724 restarting-speaker route-selection deferral.
//!
//! The startup roster is frozen before the RIB actor starts.  A configured
//! peer remains a waiter until its OPEN proves that the current session is
//! GR-capable for the family and does not carry Restart State, or proves that
//! it must be excluded.  `EoR` completion is bound to that classified session.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::mem::size_of;
use std::net::IpAddr;
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Safi};

use super::RibManager;

/// Process-wide ceiling across every typed identity retained while route
/// selection is frozen.  One million matches the documented per-neighbor
/// prefix ceiling without multiplying the safety bound by family or route
/// kind.  Overflow falls back to a complete family Loc-RIB sweep at release.
const MAX_DEFERRED_SELECTION_IDENTITIES: usize = 1_000_000;
/// Process-wide logical retained-key-data ceiling across every gated family.
/// This is deliberately deterministic key payload accounting, not allocator
/// capacity or process RSS measurement.
const MAX_DEFERRED_SELECTION_RETAINED_KEY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct DeferredSelectionLimits {
    identities: usize,
    retained_key_bytes: usize,
}

impl Default for DeferredSelectionLimits {
    fn default() -> Self {
        Self {
            identities: MAX_DEFERRED_SELECTION_IDENTITIES,
            retained_key_bytes: MAX_DEFERRED_SELECTION_RETAINED_KEY_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeferredSelectionOverflowReason {
    Identities,
    LogicalBytes,
    /// Both budgets were exhausted for the rejected identity; neither
    /// reason alone would be truthful.
    IdentitiesAndLogicalBytes,
}

impl DeferredSelectionOverflowReason {
    fn label(self) -> &'static str {
        match self {
            Self::Identities => "identities",
            Self::LogicalBytes => "logical_bytes",
            Self::IdentitiesAndLogicalBytes => "identities_and_logical_bytes",
        }
    }
}

/// Deterministic logical bytes owned by one retained identity. The charge is
/// exhaustive over the seven ledger key types and intentionally ignores hash
/// table buckets, allocator rounding, and shared-allocation pointer identity.
trait DeferredSelectionKeyCharge {
    fn logical_retained_bytes(&self) -> usize;
}

impl DeferredSelectionKeyCharge for rustbgpd_wire::Prefix {
    fn logical_retained_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

impl DeferredSelectionKeyCharge for crate::route::FlowSpecKey {
    fn logical_retained_bytes(&self) -> usize {
        use rustbgpd_wire::FlowSpecComponent;

        let mut bytes = size_of::<Self>().saturating_add(
            self.rule
                .components
                .len()
                .saturating_mul(size_of::<FlowSpecComponent>()),
        );
        for component in &self.rule.components {
            let nested = match component {
                FlowSpecComponent::IpProtocol(values)
                | FlowSpecComponent::Port(values)
                | FlowSpecComponent::DestinationPort(values)
                | FlowSpecComponent::SourcePort(values)
                | FlowSpecComponent::IcmpType(values)
                | FlowSpecComponent::IcmpCode(values)
                | FlowSpecComponent::PacketLength(values)
                | FlowSpecComponent::Dscp(values)
                | FlowSpecComponent::FlowLabel(values) => values
                    .len()
                    .saturating_mul(size_of::<rustbgpd_wire::NumericMatch>()),
                FlowSpecComponent::TcpFlags(values) | FlowSpecComponent::Fragment(values) => values
                    .len()
                    .saturating_mul(size_of::<rustbgpd_wire::BitmaskMatch>()),
                // Prefix components carry no nested op lists; a future
                // component type (`FlowSpecComponent` is non-exhaustive)
                // contributes no nested-heap estimate either — a
                // conservative under-count for the deferral budget gauge.
                _ => 0,
            };
            bytes = bytes.saturating_add(nested);
        }
        bytes
    }
}

impl DeferredSelectionKeyCharge for rustbgpd_wire::EvpnRouteKey {
    fn logical_retained_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

impl DeferredSelectionKeyCharge for crate::route::VpnRibRouteKey {
    fn logical_retained_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

impl DeferredSelectionKeyCharge for crate::route::LabeledRibRouteKey {
    fn logical_retained_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

impl DeferredSelectionKeyCharge for crate::route::BgpLsRouteKey {
    fn logical_retained_bytes(&self) -> usize {
        size_of::<Self>().saturating_add(self.nlri.payload.len())
    }
}

impl DeferredSelectionKeyCharge for crate::route::RtcRibRouteKey {
    fn logical_retained_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

#[derive(Debug, Default)]
pub(super) struct DeferredSelectionKeys {
    unicast: HashSet<rustbgpd_wire::Prefix>,
    flowspec: HashSet<crate::route::FlowSpecKey>,
    evpn: HashSet<rustbgpd_wire::EvpnRouteKey>,
    vpn: HashSet<crate::route::VpnRibRouteKey>,
    labeled: HashSet<crate::route::LabeledRibRouteKey>,
    bgpls: HashSet<crate::route::BgpLsRouteKey>,
    rtc: HashSet<crate::route::RtcRibRouteKey>,
    /// Families for which at least one distinct identity could not be retained.
    /// Release enumerates that family's Loc-RIB keys as the fail-safe source
    /// for withdrawals already absent from Adj-RIB-In.
    overflowed_families: HashSet<(Afi, Safi)>,
    /// Logical retained-key bytes charged to each gated family. Charges stay
    /// owned until that family's complete release finishes.
    retained_key_bytes_by_family: HashMap<(Afi, Safi), usize>,
    /// O(1) process-wide sum of `retained_key_bytes_by_family`.
    retained_key_bytes: usize,
    limits: DeferredSelectionLimits,
}

impl DeferredSelectionKeys {
    fn len(&self) -> usize {
        self.unicast.len()
            + self.flowspec.len()
            + self.evpn.len()
            + self.vpn.len()
            + self.labeled.len()
            + self.bgpls.len()
            + self.rtc.len()
    }

    /// Insert distinct typed identities until the process-wide ledger limit is
    /// reached.  Returns each family that entered overflow fallback during
    /// this call; an already-overflowed family stops retaining further keys.
    fn extend_bounded<'a, T>(
        set: &mut HashSet<T>,
        overflowed_families: &mut HashSet<(Afi, Safi)>,
        retained_key_bytes_by_family: &mut HashMap<(Afi, Safi), usize>,
        retained_key_bytes: &mut usize,
        identities: impl IntoIterator<Item = ((Afi, Safi), &'a T)>,
        current_len: usize,
        limits: DeferredSelectionLimits,
    ) -> Vec<((Afi, Safi), DeferredSelectionOverflowReason)>
    where
        T: Clone + DeferredSelectionKeyCharge + Eq + Hash + 'a,
    {
        let mut remaining = limits.identities.saturating_sub(current_len);
        let mut newly_overflowed = Vec::new();
        for (family, identity) in identities {
            // Once a family is sticky-overflowed, skip even the borrowed hash
            // lookup. Otherwise duplicate delivery never consumes identity or
            // byte budget and never clones the key.
            if overflowed_families.contains(&family) || set.contains(identity) {
                continue;
            }
            let charge = identity.logical_retained_bytes();
            let remaining_key_bytes = limits
                .retained_key_bytes
                .saturating_sub(*retained_key_bytes);
            let overflow_reason = match (remaining == 0, charge > remaining_key_bytes) {
                (true, true) => Some(DeferredSelectionOverflowReason::IdentitiesAndLogicalBytes),
                (true, false) => Some(DeferredSelectionOverflowReason::Identities),
                (false, true) => Some(DeferredSelectionOverflowReason::LogicalBytes),
                (false, false) => None,
            };
            if let Some(reason) = overflow_reason {
                if overflowed_families.insert(family) {
                    newly_overflowed.push((family, reason));
                }
                continue;
            }
            // Admission is proven before cloning potentially nested FlowSpec
            // or BGP-LS data into the ledger.
            if set.insert(identity.clone()) {
                remaining -= 1;
                *retained_key_bytes = retained_key_bytes.saturating_add(charge);
                let family_bytes = retained_key_bytes_by_family.entry(family).or_default();
                *family_bytes = family_bytes.saturating_add(charge);
            }
        }
        newly_overflowed
    }

    fn complete_family_release(&mut self, family: (Afi, Safi)) {
        self.overflowed_families.remove(&family);
        if let Some(released) = self.retained_key_bytes_by_family.remove(&family) {
            self.retained_key_bytes = self.retained_key_bytes.saturating_sub(released);
        }
    }
}
use super::helpers::{afi_safi_label, gauge_val};

/// One peer in the startup-frozen RFC 4724 waiter roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionDeferralWaiterConfig {
    /// Static peer address.
    pub peer: IpAddr,
    /// Configured families for which this peer may become an `EoR` waiter.
    pub families: Vec<(Afi, Safi)>,
}

/// Process-start configuration for restarting-speaker selection deferral.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionDeferralConfig {
    /// Upper bound shared by every per-family deferral gate.
    pub timeout: Duration,
    /// Complete static-peer roster, captured before any session starts.
    pub waiters: Vec<SelectionDeferralWaiterConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectionDeferralReleaseReason {
    AllEndOfRib,
    CollisionRefreshComplete,
    TimerExpired,
    /// The gate completed without any waiter delivering a completion signal:
    /// every roster entry was excluded (or deleted from configuration), so
    /// zero End-of-RIB or refresh markers were consumed.
    AllExcluded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectionDeferralTransition {
    Stage {
        family: (Afi, Safi),
    },
    Release {
        family: (Afi, Safi),
        already_staged: bool,
        release_reason: SelectionDeferralReleaseReason,
    },
}

impl SelectionDeferralReleaseReason {
    fn label(self) -> &'static str {
        match self {
            Self::AllEndOfRib => "all_eor",
            Self::CollisionRefreshComplete => "collision_refresh",
            Self::TimerExpired => "timer",
            Self::AllExcluded => "all_excluded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaiterState {
    AwaitingSession,
    AwaitingEor {
        session_id: u64,
    },
    AwaitingRefresh {
        session_id: u64,
        begin_received: bool,
    },
    Satisfied {
        session_id: u64,
    },
    Excluded {
        session_id: u64,
    },
}

impl WaiterState {
    fn snapshot(self) -> (&'static str, Option<u64>) {
        match self {
            Self::AwaitingSession => ("awaiting_session", None),
            Self::AwaitingEor { session_id } => ("awaiting_eor", Some(session_id)),
            Self::AwaitingRefresh { session_id, .. } => ("awaiting_refresh", Some(session_id)),
            Self::Satisfied { session_id } => ("satisfied", Some(session_id)),
            Self::Excluded { session_id } => ("excluded", Some(session_id)),
        }
    }
}

#[derive(Debug)]
struct FamilyGate {
    waiters: HashMap<IpAddr, WaiterState>,
    selection_staged: bool,
}

#[derive(Debug)]
struct ReleasedFamily {
    reason: SelectionDeferralReleaseReason,
    waiters: HashMap<IpAddr, WaiterState>,
}

/// Actor-owned selection-deferral state. Released families are retained in
/// `released` for process-lifetime operator diagnostics. Every `active` gate
/// suppresses convergence markers; an active gate whose selection is not yet
/// staged also suppresses route selection and route payloads.
#[derive(Debug)]
pub(super) struct SelectionDeferral {
    deadline: tokio::time::Instant,
    active: HashMap<(Afi, Safi), FamilyGate>,
    released: HashMap<(Afi, Safi), ReleasedFamily>,
    /// Address-only RIB identity cannot disambiguate scoped duplicate peers.
    /// Keep such peers blocked until the timer rather than let one `EoR` satisfy
    /// both configured sessions.
    ambiguous_peers: HashSet<IpAddr>,
}

impl SelectionDeferral {
    fn blocking_waiters(gate: &FamilyGate) -> usize {
        gate.waiters
            .values()
            .filter(|state| {
                matches!(
                    state,
                    WaiterState::AwaitingSession
                        | WaiterState::AwaitingEor { .. }
                        | WaiterState::AwaitingRefresh { .. }
                )
            })
            .count()
    }

    fn complete(gate: &FamilyGate) -> bool {
        Self::blocking_waiters(gate) == 0
    }

    fn selection_blocking_waiters(gate: &FamilyGate) -> usize {
        gate.waiters
            .values()
            .filter(|state| {
                matches!(
                    state,
                    WaiterState::AwaitingSession | WaiterState::AwaitingEor { .. }
                )
            })
            .count()
    }

    pub(super) fn new(config: SelectionDeferralConfig, metrics: &BgpMetrics) -> Option<Self> {
        let mut active: HashMap<(Afi, Safi), FamilyGate> = HashMap::new();
        let mut seen = HashSet::new();
        let mut ambiguous_peers = HashSet::new();
        for waiter in config.waiters {
            if !seen.insert(waiter.peer) {
                ambiguous_peers.insert(waiter.peer);
            }
            for family in waiter.families {
                active
                    .entry(family)
                    .or_insert_with(|| FamilyGate {
                        waiters: HashMap::new(),
                        selection_staged: false,
                    })
                    .waiters
                    .insert(waiter.peer, WaiterState::AwaitingSession);
            }
        }
        for peer in &ambiguous_peers {
            tracing::warn!(%peer, "duplicate static peer address in selection-deferral roster; waiting for timer because scoped identity is ambiguous");
        }
        if active.is_empty() || config.timeout.is_zero() {
            return None;
        }
        for (&(afi, safi), gate) in &active {
            let label = afi_safi_label(afi, safi);
            metrics.set_selection_deferral_active(label, true);
            metrics.set_selection_deferral_waiters(label, gauge_val(Self::blocking_waiters(gate)));
        }
        Some(Self {
            deadline: tokio::time::Instant::now() + config.timeout,
            active,
            released: HashMap::new(),
            ambiguous_peers,
        })
    }

    pub(super) fn is_gated(&self, family: (Afi, Safi)) -> bool {
        self.active.contains_key(&family)
    }

    pub(super) fn selection_deferred(&self, family: (Afi, Safi)) -> bool {
        self.active
            .get(&family)
            .is_some_and(|gate| !gate.selection_staged)
    }

    fn has_deferred_selection(&self) -> bool {
        self.active.values().any(|gate| !gate.selection_staged)
    }

    fn evaluate_family(
        &mut self,
        family: (Afi, Safi),
        release_reason: SelectionDeferralReleaseReason,
    ) -> Option<SelectionDeferralTransition> {
        let gate = self.active.get_mut(&family)?;
        let transition = if Self::complete(gate) {
            // A gate can complete without any waiter having delivered a
            // completion signal (every roster entry excluded or deleted).
            // Recording the event reason there would claim End-of-RIB or
            // refresh markers that were never received.
            let release_reason = if gate
                .waiters
                .values()
                .any(|state| matches!(state, WaiterState::Satisfied { .. }))
            {
                release_reason
            } else {
                SelectionDeferralReleaseReason::AllExcluded
            };
            SelectionDeferralTransition::Release {
                family,
                already_staged: gate.selection_staged,
                release_reason,
            }
        } else if !gate.selection_staged && Self::selection_blocking_waiters(gate) == 0 {
            gate.selection_staged = true;
            SelectionDeferralTransition::Stage { family }
        } else {
            return None;
        };
        Some(transition)
    }

    pub(super) fn deadline(&self) -> Option<tokio::time::Instant> {
        (!self.active.is_empty()).then_some(self.deadline)
    }

    pub(super) fn peer_snapshot(
        &self,
        peer: IpAddr,
    ) -> Vec<crate::update::SelectionDeferralPeerFamilyState> {
        let now = tokio::time::Instant::now();
        let remaining_millis =
            u64::try_from(self.deadline.saturating_duration_since(now).as_millis())
                .unwrap_or(u64::MAX);
        let mut rows = Vec::with_capacity(self.active.len() + self.released.len());
        for (&(afi, safi), gate) in &self.active {
            let (waiter_state, waiter_session_id) = gate
                .waiters
                .get(&peer)
                .copied()
                .map_or(("not_in_roster", None), WaiterState::snapshot);
            rows.push(crate::update::SelectionDeferralPeerFamilyState {
                afi,
                safi,
                active: true,
                waiter_state: waiter_state.to_string(),
                waiter_session_id,
                blocking_waiters: u64::try_from(Self::blocking_waiters(gate)).unwrap_or(u64::MAX),
                remaining_millis,
                release_reason: String::new(),
            });
        }
        for (&(afi, safi), released) in &self.released {
            let (waiter_state, waiter_session_id) = released
                .waiters
                .get(&peer)
                .copied()
                .map_or(("not_in_roster", None), WaiterState::snapshot);
            rows.push(crate::update::SelectionDeferralPeerFamilyState {
                afi,
                safi,
                active: false,
                waiter_state: waiter_state.to_string(),
                waiter_session_id,
                blocking_waiters: 0,
                remaining_millis: 0,
                release_reason: released.reason.label().to_string(),
            });
        }
        rows.sort_by_key(|row| (row.afi as u16, row.safi as u8));
        rows
    }

    /// Bind a startup waiter to the currently active transport generation, or
    /// remove it when OPEN proves that RFC 4724 says not to wait for it.
    pub(super) fn classify_session(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        peer_restart_state: bool,
        peer_gr_families: &HashSet<(Afi, Safi)>,
        metrics: &BgpMetrics,
    ) -> Vec<SelectionDeferralTransition> {
        if session_id == 0 {
            tracing::warn!(%peer, "selection-deferral waiter received unstamped PeerUp; keeping it blocked");
            return Vec::new();
        }
        if self.ambiguous_peers.contains(&peer) {
            tracing::warn!(
                %peer,
                "selection-deferral waiter address is ambiguous in the configured roster; keeping it blocked"
            );
            return Vec::new();
        }
        let families: Vec<_> = self.active.keys().copied().collect();
        let mut transitions = Vec::new();
        for family in families {
            let Some(gate) = self.active.get_mut(&family) else {
                continue;
            };
            if !gate.waiters.contains_key(&peer) {
                continue;
            }
            if peer_restart_state || !peer_gr_families.contains(&family) {
                gate.waiters
                    .insert(peer, WaiterState::Excluded { session_id });
            } else {
                gate.waiters
                    .insert(peer, WaiterState::AwaitingEor { session_id });
            }
            metrics.set_selection_deferral_waiters(
                afi_safi_label(family.0, family.1),
                gauge_val(Self::blocking_waiters(gate)),
            );
            if let Some(transition) =
                self.evaluate_family(family, SelectionDeferralReleaseReason::AllEndOfRib)
            {
                transitions.push(transition);
            }
        }
        transitions
    }

    /// Hold the exact session recovered by collision failback until a
    /// post-failback `BoRR`/`EoRR` pair proves that its Adj-RIB-In replay
    /// completed. Only an unambiguous, stamped survivor whose current roster
    /// state was re-armed by the active session's teardown may take this path.
    ///
    /// The refresh wait applies the same OPEN gating as `classify_session`:
    /// a Restart-State or non-GR family is excluded, and a survivor that did
    /// not negotiate enhanced route refresh (RFC 7313) is excluded too — it
    /// will never produce the `BoRR`/`EoRR` pair, so `AwaitingRefresh` would
    /// convergence-hold the family for the entire deferral window.
    ///
    /// `Some` means at least one active family was classified; the contained
    /// transitions stage any family whose ordinary waiters are already done.
    /// `None` leaves every waiter unchanged.
    pub(super) fn await_collision_failback_refresh(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        peer_restart_state: bool,
        peer_gr_families: &HashSet<(Afi, Safi)>,
        peer_enhanced_refresh: bool,
        metrics: &BgpMetrics,
    ) -> Option<Vec<SelectionDeferralTransition>> {
        if session_id == 0 {
            tracing::warn!(
                %peer,
                "selection-deferral collision-failback survivor is unstamped; keeping it blocked"
            );
            return None;
        }
        if self.ambiguous_peers.contains(&peer) {
            tracing::warn!(
                %peer,
                session_id,
                "selection-deferral collision-failback survivor address is ambiguous; keeping it blocked"
            );
            return None;
        }

        let families: Vec<_> = self.active.keys().copied().collect();
        let mut classified = false;
        let mut transitions = Vec::new();
        for family in families {
            let Some(gate) = self.active.get_mut(&family) else {
                continue;
            };
            if gate.waiters.get(&peer) != Some(&WaiterState::AwaitingSession) {
                continue;
            }
            let state = if peer_restart_state
                || !peer_gr_families.contains(&family)
                || !peer_enhanced_refresh
            {
                WaiterState::Excluded { session_id }
            } else {
                WaiterState::AwaitingRefresh {
                    session_id,
                    begin_received: false,
                }
            };
            gate.waiters.insert(peer, state);
            classified = true;
            metrics.set_selection_deferral_waiters(
                afi_safi_label(family.0, family.1),
                gauge_val(Self::blocking_waiters(gate)),
            );
            if let Some(transition) =
                self.evaluate_family(family, SelectionDeferralReleaseReason::AllEndOfRib)
            {
                transitions.push(transition);
            }
        }
        classified.then_some(transitions)
    }

    /// Revert a current-session waiter to the not-yet-established state.  A
    /// flap cannot shrink the frozen cohort and accidentally release a family.
    pub(super) fn session_down(&mut self, peer: IpAddr, session_id: u64, metrics: &BgpMetrics) {
        for (&family, gate) in &mut self.active {
            if matches!(
                gate.waiters.get(&peer),
                Some(
                    WaiterState::AwaitingEor { session_id: current }
                        | WaiterState::AwaitingRefresh {
                            session_id: current,
                            ..
                        }
                        | WaiterState::Satisfied { session_id: current }
                        | WaiterState::Excluded { session_id: current }
                ) if *current == session_id
            ) {
                gate.waiters.insert(peer, WaiterState::AwaitingSession);
                metrics.set_selection_deferral_waiters(
                    afi_safi_label(family.0, family.1),
                    gauge_val(Self::blocking_waiters(gate)),
                );
            }
        }
    }

    /// Remove a deleted peer's waiters outright: configuration removed the
    /// neighbor, so no future session can satisfy or re-arm them. Unlike
    /// `session_down` (a flap must not shrink the frozen cohort), deletion
    /// is authoritative — any family whose remaining waiters are already
    /// done completes here instead of blocking until the timer. An
    /// ambiguous roster address stays fail-closed: address-only identity
    /// cannot tell which of the duplicate configured peers was deleted.
    pub(super) fn peer_deleted(
        &mut self,
        peer: IpAddr,
        metrics: &BgpMetrics,
    ) -> Vec<SelectionDeferralTransition> {
        if self.ambiguous_peers.contains(&peer) {
            tracing::warn!(
                %peer,
                "deleted peer address is ambiguous in the selection-deferral roster; keeping its waiters blocked until the timer"
            );
            return Vec::new();
        }
        let families: Vec<_> = self.active.keys().copied().collect();
        let mut transitions = Vec::new();
        for family in families {
            let Some(gate) = self.active.get_mut(&family) else {
                continue;
            };
            if gate.waiters.remove(&peer).is_none() {
                continue;
            }
            metrics.set_selection_deferral_waiters(
                afi_safi_label(family.0, family.1),
                gauge_val(Self::blocking_waiters(gate)),
            );
            if let Some(transition) =
                self.evaluate_family(family, SelectionDeferralReleaseReason::AllEndOfRib)
            {
                transitions.push(transition);
            }
        }
        transitions
    }

    pub(super) fn end_of_rib(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
        metrics: &BgpMetrics,
    ) -> Option<SelectionDeferralTransition> {
        if session_id == 0 {
            return None;
        }
        let gate = self.active.get_mut(&family)?;
        if gate.waiters.get(&peer) != Some(&WaiterState::AwaitingEor { session_id }) {
            return None;
        }
        gate.waiters
            .insert(peer, WaiterState::Satisfied { session_id });
        metrics.set_selection_deferral_waiters(
            afi_safi_label(family.0, family.1),
            gauge_val(Self::blocking_waiters(gate)),
        );
        self.evaluate_family(family, SelectionDeferralReleaseReason::AllEndOfRib)
    }

    pub(super) fn begin_route_refresh(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
    ) -> Option<SelectionDeferralTransition> {
        let gate = self.active.get_mut(&family)?;
        if gate.waiters.get(&peer)
            != Some(&WaiterState::AwaitingRefresh {
                session_id,
                begin_received: false,
            })
        {
            return None;
        }
        gate.waiters.insert(
            peer,
            WaiterState::AwaitingRefresh {
                session_id,
                begin_received: true,
            },
        );
        self.evaluate_family(family, SelectionDeferralReleaseReason::AllEndOfRib)
    }

    pub(super) fn end_route_refresh(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
        metrics: &BgpMetrics,
    ) -> Option<SelectionDeferralTransition> {
        let gate = self.active.get_mut(&family)?;
        if gate.waiters.get(&peer)
            != Some(&WaiterState::AwaitingRefresh {
                session_id,
                begin_received: true,
            })
        {
            return None;
        }
        gate.waiters
            .insert(peer, WaiterState::Satisfied { session_id });
        metrics.set_selection_deferral_waiters(
            afi_safi_label(family.0, family.1),
            gauge_val(Self::blocking_waiters(gate)),
        );
        self.evaluate_family(
            family,
            SelectionDeferralReleaseReason::CollisionRefreshComplete,
        )
    }

    pub(super) fn expire(&mut self, metrics: &BgpMetrics) -> Vec<(Afi, Safi)> {
        let families: Vec<_> = self.active.keys().copied().collect();
        for &family in &families {
            self.release(
                family,
                SelectionDeferralReleaseReason::TimerExpired,
                metrics,
            );
        }
        families
    }

    fn release(
        &mut self,
        family: (Afi, Safi),
        reason: SelectionDeferralReleaseReason,
        metrics: &BgpMetrics,
    ) {
        let Some(gate) = self.active.remove(&family) else {
            return;
        };
        self.released.insert(
            family,
            ReleasedFamily {
                reason,
                waiters: gate.waiters,
            },
        );
        let label = afi_safi_label(family.0, family.1);
        metrics.set_selection_deferral_active(label, false);
        metrics.set_selection_deferral_waiters(label, 0);
        metrics.record_selection_deferral_release(label, reason.label());
        if reason == SelectionDeferralReleaseReason::TimerExpired {
            metrics.record_selection_deferral_timeout(label);
        }
    }
}

impl RibManager {
    fn deferred_selection_recording_active(&self) -> bool {
        self.selection_deferral
            .as_ref()
            .is_some_and(SelectionDeferral::has_deferred_selection)
    }

    fn record_selection_ledger_overflows(
        &self,
        families: Vec<((Afi, Safi), DeferredSelectionOverflowReason)>,
    ) {
        for ((afi, safi), reason) in families {
            tracing::warn!(
                ?afi,
                ?safi,
                reason = reason.label(),
                identity_cap = MAX_DEFERRED_SELECTION_IDENTITIES,
                retained_key_bytes_cap = MAX_DEFERRED_SELECTION_RETAINED_KEY_BYTES,
                "retaining a selection-deferral identity would exceed a process-wide bound; release will sweep the complete Adj-RIB-In and Loc-RIB family"
            );
            self.metrics
                .record_selection_deferral_ledger_overflow(afi_safi_label(afi, safi));
        }
    }

    pub(super) fn record_deferred_unicast(&mut self, affected: &HashSet<rustbgpd_wire::Prefix>) {
        self.record_deferred_unicast_bounded(affected, self.deferred_selection_keys.limits);
    }

    fn record_deferred_unicast_bounded(
        &mut self,
        affected: &HashSet<rustbgpd_wire::Prefix>,
        limits: DeferredSelectionLimits,
    ) {
        let Some(selection) = self
            .selection_deferral
            .as_ref()
            .filter(|selection| selection.has_deferred_selection())
        else {
            return;
        };
        let deferred = affected.iter().filter_map(|prefix| {
            let family = super::helpers::prefix_family(prefix);
            selection
                .selection_deferred(family)
                .then_some((family, prefix))
        });
        let current_len = self.deferred_selection_keys.len();
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut self.deferred_selection_keys.unicast,
            &mut self.deferred_selection_keys.overflowed_families,
            &mut self.deferred_selection_keys.retained_key_bytes_by_family,
            &mut self.deferred_selection_keys.retained_key_bytes,
            deferred,
            current_len,
            limits,
        );
        self.record_selection_ledger_overflows(newly_overflowed);
    }

    pub(super) fn record_deferred_flowspec(
        &mut self,
        affected: &HashSet<crate::route::FlowSpecKey>,
    ) {
        let Some(selection) = self
            .selection_deferral
            .as_ref()
            .filter(|selection| selection.has_deferred_selection())
        else {
            return;
        };
        let deferred = affected.iter().filter_map(|key| {
            let family = (key.afi, Safi::FlowSpec);
            selection
                .selection_deferred(family)
                .then_some((family, key))
        });
        let current_len = self.deferred_selection_keys.len();
        let limits = self.deferred_selection_keys.limits;
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut self.deferred_selection_keys.flowspec,
            &mut self.deferred_selection_keys.overflowed_families,
            &mut self.deferred_selection_keys.retained_key_bytes_by_family,
            &mut self.deferred_selection_keys.retained_key_bytes,
            deferred,
            current_len,
            limits,
        );
        self.record_selection_ledger_overflows(newly_overflowed);
    }

    pub(super) fn record_deferred_evpn(&mut self, affected: &HashSet<rustbgpd_wire::EvpnRouteKey>) {
        if !self.deferred_selection_recording_active() {
            return;
        }
        if self.selection_deferred((Afi::L2Vpn, Safi::Evpn)) {
            let deferred = affected.iter().map(|key| ((Afi::L2Vpn, Safi::Evpn), key));
            let current_len = self.deferred_selection_keys.len();
            let limits = self.deferred_selection_keys.limits;
            let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                &mut self.deferred_selection_keys.evpn,
                &mut self.deferred_selection_keys.overflowed_families,
                &mut self.deferred_selection_keys.retained_key_bytes_by_family,
                &mut self.deferred_selection_keys.retained_key_bytes,
                deferred,
                current_len,
                limits,
            );
            self.record_selection_ledger_overflows(newly_overflowed);
        }
    }

    pub(super) fn record_deferred_vpn(&mut self, affected: &HashSet<crate::route::VpnRibRouteKey>) {
        let Some(selection) = self
            .selection_deferral
            .as_ref()
            .filter(|selection| selection.has_deferred_selection())
        else {
            return;
        };
        let deferred = affected.iter().filter_map(|key| {
            let family = key.afi_safi();
            selection
                .selection_deferred(family)
                .then_some((family, key))
        });
        let current_len = self.deferred_selection_keys.len();
        let limits = self.deferred_selection_keys.limits;
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut self.deferred_selection_keys.vpn,
            &mut self.deferred_selection_keys.overflowed_families,
            &mut self.deferred_selection_keys.retained_key_bytes_by_family,
            &mut self.deferred_selection_keys.retained_key_bytes,
            deferred,
            current_len,
            limits,
        );
        self.record_selection_ledger_overflows(newly_overflowed);
    }

    pub(super) fn record_deferred_labeled(
        &mut self,
        affected: &HashSet<crate::route::LabeledRibRouteKey>,
    ) {
        let Some(selection) = self
            .selection_deferral
            .as_ref()
            .filter(|selection| selection.has_deferred_selection())
        else {
            return;
        };
        let deferred = affected.iter().filter_map(|key| {
            let family = key.afi_safi();
            selection
                .selection_deferred(family)
                .then_some((family, key))
        });
        let current_len = self.deferred_selection_keys.len();
        let limits = self.deferred_selection_keys.limits;
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut self.deferred_selection_keys.labeled,
            &mut self.deferred_selection_keys.overflowed_families,
            &mut self.deferred_selection_keys.retained_key_bytes_by_family,
            &mut self.deferred_selection_keys.retained_key_bytes,
            deferred,
            current_len,
            limits,
        );
        self.record_selection_ledger_overflows(newly_overflowed);
    }

    pub(super) fn record_deferred_bgpls(
        &mut self,
        affected: &HashSet<crate::route::BgpLsRouteKey>,
    ) {
        let Some(selection) = self
            .selection_deferral
            .as_ref()
            .filter(|selection| selection.has_deferred_selection())
        else {
            return;
        };
        let deferred = affected.iter().filter_map(|key| {
            let family = key.family.to_afi_safi();
            selection
                .selection_deferred(family)
                .then_some((family, key))
        });
        let current_len = self.deferred_selection_keys.len();
        let limits = self.deferred_selection_keys.limits;
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut self.deferred_selection_keys.bgpls,
            &mut self.deferred_selection_keys.overflowed_families,
            &mut self.deferred_selection_keys.retained_key_bytes_by_family,
            &mut self.deferred_selection_keys.retained_key_bytes,
            deferred,
            current_len,
            limits,
        );
        self.record_selection_ledger_overflows(newly_overflowed);
    }

    pub(super) fn record_deferred_rtc(&mut self, affected: &HashSet<crate::route::RtcRibRouteKey>) {
        if !self.deferred_selection_recording_active() {
            return;
        }
        if self.selection_deferred(crate::route::RtcRibRouteKey::afi_safi()) {
            let family = crate::route::RtcRibRouteKey::afi_safi();
            let deferred = affected.iter().map(|key| (family, key));
            let current_len = self.deferred_selection_keys.len();
            let limits = self.deferred_selection_keys.limits;
            let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                &mut self.deferred_selection_keys.rtc,
                &mut self.deferred_selection_keys.overflowed_families,
                &mut self.deferred_selection_keys.retained_key_bytes_by_family,
                &mut self.deferred_selection_keys.retained_key_bytes,
                deferred,
                current_len,
                limits,
            );
            self.record_selection_ledger_overflows(newly_overflowed);
        }
    }

    #[cfg(test)]
    pub(in crate::manager) fn record_deferred_unicast_with_test_limit(
        &mut self,
        affected: &HashSet<rustbgpd_wire::Prefix>,
        limit: usize,
    ) {
        self.record_deferred_unicast_bounded(
            affected,
            DeferredSelectionLimits {
                identities: limit,
                retained_key_bytes: MAX_DEFERRED_SELECTION_RETAINED_KEY_BYTES,
            },
        );
    }

    #[cfg(test)]
    pub(in crate::manager) fn set_deferred_selection_limits_for_test(
        &mut self,
        identities: usize,
        retained_key_bytes: usize,
    ) {
        self.deferred_selection_keys.limits = DeferredSelectionLimits {
            identities,
            retained_key_bytes,
        };
    }

    #[cfg(test)]
    pub(in crate::manager) fn mark_deferred_selection_overflow_for_test(
        &mut self,
        family: (Afi, Safi),
    ) {
        self.deferred_selection_keys
            .overflowed_families
            .insert(family);
    }

    #[cfg(test)]
    pub(in crate::manager) fn recompute_released_selection_family_for_test(
        &mut self,
        family: (Afi, Safi),
    ) {
        self.recompute_released_selection_family(family);
    }

    #[cfg(test)]
    pub(in crate::manager) fn deferred_selection_ledger_state_for_test(
        &self,
        family: (Afi, Safi),
    ) -> (usize, bool) {
        (
            self.deferred_selection_keys.retained_key_bytes,
            self.deferred_selection_keys
                .overflowed_families
                .contains(&family),
        )
    }

    /// Consume a current-session `EoR` in the startup gate. The caller invokes
    /// the ordinary GR/LLGR `EoR` handler after this, then recomputes the released
    /// family against the complete Adj-RIB-In cohort.
    pub(super) fn selection_deferral_end_of_rib(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
    ) -> Option<SelectionDeferralTransition> {
        self.selection_deferral
            .as_mut()
            .and_then(|selection| selection.end_of_rib(peer, session_id, family, &self.metrics))
    }

    pub(super) fn selection_deferral_begin_route_refresh(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
    ) -> Option<SelectionDeferralTransition> {
        self.selection_deferral
            .as_mut()
            .and_then(|selection| selection.begin_route_refresh(peer, session_id, family))
    }

    pub(super) fn selection_deferral_end_route_refresh(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
    ) -> Option<SelectionDeferralTransition> {
        self.selection_deferral.as_mut().and_then(|selection| {
            selection.end_route_refresh(peer, session_id, family, &self.metrics)
        })
    }

    pub(super) fn expire_selection_deferral(&mut self) {
        let families = self
            .selection_deferral
            .as_mut()
            .map_or_else(Vec::new, |selection| selection.expire(&self.metrics));
        self.release_selection_families(&families, "Selection_Deferral_Timer expired");
    }

    pub(super) fn next_selection_deferral_deadline(&self) -> Option<tokio::time::Instant> {
        self.selection_deferral
            .as_ref()
            .and_then(SelectionDeferral::deadline)
    }

    /// Complete a family release. Ordinary release runs the delayed selection;
    /// a timer fallback may recompute a family that collision failback staged
    /// earlier. All identity sets come from Adj-RIB-In, which continued
    /// accepting current-session updates while Loc-RIB selection was frozen.
    pub(super) fn release_selection_families(
        &mut self,
        families: &[(Afi, Safi)],
        reason: &'static str,
    ) {
        if !families.is_empty() {
            // Timer expiry and all-EoR release can recompute Loc-RIB directly
            // without a new RibUpdate. Fence every view before the release.
            self.advance_all_route_pages();
        }
        for &family in families {
            self.complete_selection_family(family, false, reason);
        }
    }

    pub(super) fn apply_selection_deferral_transitions(
        &mut self,
        transitions: impl IntoIterator<Item = SelectionDeferralTransition>,
        reason: &'static str,
    ) {
        for transition in transitions {
            match transition {
                SelectionDeferralTransition::Stage { family } => {
                    tracing::info!(
                        afi = ?family.0,
                        safi = ?family.1,
                        reason,
                        "RFC 4724 route selection staged while collision-failback convergence remains held"
                    );
                    self.recompute_released_selection_family(family);
                }
                SelectionDeferralTransition::Release {
                    family,
                    already_staged,
                    release_reason,
                } => {
                    if let Some(selection) = self.selection_deferral.as_mut() {
                        selection.release(family, release_reason, &self.metrics);
                    }
                    self.complete_selection_family(family, already_staged, reason);
                }
            }
        }
    }

    fn complete_selection_family(
        &mut self,
        family: (Afi, Safi),
        already_staged: bool,
        reason: &'static str,
    ) {
        tracing::info!(
            afi = ?family.0,
            safi = ?family.1,
            reason,
            "RFC 4724 route-selection deferral released"
        );
        if !already_staged {
            self.recompute_released_selection_family(family);
        }
        // Existing sessions received no initial table and no EoR while
        // gated. Queue the marker only after the released selection has
        // been staged; dirty peers keep it pending until their full resync
        // succeeds, preserving table-before-EoR ordering.
        let peers: Vec<_> = self
            .peer_sendable_families
            .iter()
            .filter_map(|(&peer, sendable)| sendable.contains(&family).then_some(peer))
            .collect();
        for peer in peers {
            self.pending_eor.entry(peer).or_default().insert(family);
            if !self.dirty_peers.contains(&peer) {
                self.flush_pending_eor(peer);
            }
        }
        let refresh_peers: Vec<_> = self
            .selection_deferred_refresh
            .iter()
            .filter_map(|(&peer, families)| families.contains(&family).then_some(peer))
            .collect();
        for peer in refresh_peers {
            if let Some(families) = self.selection_deferred_refresh.get_mut(&peer) {
                families.remove(&family);
                if families.is_empty() {
                    self.selection_deferred_refresh.remove(&peer);
                }
            }
            if self.dirty_peers.contains(&peer) {
                // The dirty-resync success path flushes or piggybacks the
                // convergence EoR before retrying this response.
                self.pending_refresh.entry(peer).or_default().insert(family);
            } else {
                // The convergence EoR loop above already queued/flushed the
                // genuine EoR for every sendable peer, so the response must
                // not carry its own `end_of_rib` entry — a plain-refresh
                // (RFC 2918) peer would receive a duplicate empty-UPDATE
                // EoR (RFC 7313 peers get the EoRR demarcation regardless).
                let convergence_eor_queued = self
                    .peer_sendable_families
                    .get(&peer)
                    .is_some_and(|sendable| sendable.contains(&family));
                self.send_route_refresh_response_inner(
                    peer,
                    family.0,
                    family.1,
                    convergence_eor_queued,
                );
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "release must sweep every typed RIB family from one atomic family gate"
    )]
    fn recompute_released_selection_family(&mut self, family: (Afi, Safi)) {
        let overflowed = self
            .deferred_selection_keys
            .overflowed_families
            .contains(&family);
        let mut prefixes: HashSet<_> = self
            .ribs
            .values()
            .flat_map(crate::adj_rib_in::AdjRibIn::iter)
            .filter(|route| super::helpers::prefix_family(&route.prefix) == family)
            .map(|route| route.prefix)
            .collect();
        if overflowed && family.1 == Safi::Unicast {
            prefixes.extend(
                self.loc_rib
                    .iter()
                    .filter(|route| super::helpers::prefix_family(&route.prefix) == family)
                    .map(|route| route.prefix),
            );
        }
        prefixes.extend(
            self.deferred_selection_keys
                .unicast
                .iter()
                .filter(|prefix| super::helpers::prefix_family(prefix) == family)
                .copied(),
        );
        self.deferred_selection_keys
            .unicast
            .retain(|prefix| super::helpers::prefix_family(prefix) != family);
        if !prefixes.is_empty() {
            let changed = self.recompute_best(&prefixes);
            self.distribute_changes(&changed, &prefixes);
        }

        let mut flowspec: HashSet<_> = self
            .ribs
            .values()
            .flat_map(crate::adj_rib_in::AdjRibIn::iter_flowspec)
            .filter(|route| (route.afi, Safi::FlowSpec) == family)
            .map(crate::route::FlowSpecRoute::selection_key)
            .collect();
        if overflowed && family.1 == Safi::FlowSpec {
            flowspec.extend(
                self.loc_rib
                    .iter_flowspec()
                    .filter(|route| (route.afi, Safi::FlowSpec) == family)
                    .map(crate::route::FlowSpecRoute::selection_key),
            );
        }
        flowspec.extend(
            self.deferred_selection_keys
                .flowspec
                .iter()
                .filter(|key| (key.afi, Safi::FlowSpec) == family)
                .cloned(),
        );
        self.deferred_selection_keys
            .flowspec
            .retain(|key| (key.afi, Safi::FlowSpec) != family);
        if !flowspec.is_empty() {
            self.recompute_and_distribute_flowspec(&flowspec);
        }

        if family == (Afi::L2Vpn, Safi::Evpn) {
            let mut evpn: HashSet<_> = self
                .ribs
                .values()
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_evpn)
                .map(crate::route::EvpnRibRoute::key)
                .collect();
            if overflowed {
                evpn.extend(
                    self.loc_rib
                        .iter_evpn()
                        .map(crate::route::EvpnRibRoute::key),
                );
            }
            evpn.extend(self.deferred_selection_keys.evpn.drain());
            if !evpn.is_empty() {
                self.recompute_and_distribute_evpn(&evpn);
            }
        }

        let mut vpn: HashSet<_> = self
            .ribs
            .values()
            .flat_map(crate::adj_rib_in::AdjRibIn::iter_vpn)
            .filter(|route| route.afi_safi() == family)
            .map(crate::route::VpnRibRoute::key)
            .collect();
        if overflowed && family.1 == Safi::MplsVpn {
            vpn.extend(
                self.loc_rib
                    .iter_vpn()
                    .filter(|route| route.afi_safi() == family)
                    .map(crate::route::VpnRibRoute::key),
            );
        }
        vpn.extend(
            self.deferred_selection_keys
                .vpn
                .iter()
                .filter(|key| key.afi_safi() == family)
                .cloned(),
        );
        self.deferred_selection_keys
            .vpn
            .retain(|key| key.afi_safi() != family);
        if !vpn.is_empty() {
            self.recompute_vpn_keys(&vpn);
        }

        let mut labeled: HashSet<_> = self
            .ribs
            .values()
            .flat_map(crate::adj_rib_in::AdjRibIn::iter_labeled)
            .filter(|route| route.afi_safi() == family)
            .map(crate::route::LabeledRibRoute::key)
            .collect();
        if overflowed && family.1 == Safi::LabeledUnicast {
            labeled.extend(
                self.loc_rib
                    .iter_labeled()
                    .filter(|route| route.afi_safi() == family)
                    .map(crate::route::LabeledRibRoute::key),
            );
        }
        labeled.extend(
            self.deferred_selection_keys
                .labeled
                .iter()
                .filter(|key| key.afi_safi() == family)
                .copied(),
        );
        self.deferred_selection_keys
            .labeled
            .retain(|key| key.afi_safi() != family);
        if !labeled.is_empty() {
            self.recompute_labeled_keys(&labeled);
        }

        let mut bgpls: HashSet<_> = self
            .ribs
            .values()
            .flat_map(crate::adj_rib_in::AdjRibIn::iter_bgpls)
            .filter(|route| route.family.to_afi_safi() == family)
            .map(crate::route::BgpLsRibRoute::key)
            .collect();
        if overflowed && matches!(family.1, Safi::BgpLs | Safi::BgpLsVpn) {
            bgpls.extend(
                self.loc_rib
                    .iter_bgpls()
                    .filter(|route| route.family.to_afi_safi() == family)
                    .map(crate::route::BgpLsRibRoute::key),
            );
        }
        bgpls.extend(
            self.deferred_selection_keys
                .bgpls
                .iter()
                .filter(|key| key.family.to_afi_safi() == family)
                .cloned(),
        );
        self.deferred_selection_keys
            .bgpls
            .retain(|key| key.family.to_afi_safi() != family);
        if !bgpls.is_empty() {
            self.recompute_bgpls_keys(&bgpls);
        }

        if family == crate::route::RtcRibRouteKey::afi_safi() {
            let mut rtc: HashSet<_> = self
                .ribs
                .values()
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_rtc)
                .map(crate::route::RtcRibRoute::key)
                .collect();
            if overflowed {
                rtc.extend(self.loc_rib.iter_rtc().map(crate::route::RtcRibRoute::key));
            }
            rtc.extend(self.deferred_selection_keys.rtc.drain());
            if !rtc.is_empty() {
                self.recompute_rtc_keys(&rtc);
            }
            let rtc_peers: Vec<_> = self.peer_rt_membership.keys().copied().collect();
            for peer in rtc_peers {
                self.rebuild_rtc_membership_and_restage_vpn(peer);
            }
        }
        // Overflow state and logical byte budget stay sticky until every
        // typed store and RTC side effect for the family has completed.
        self.deferred_selection_keys.complete_family_release(family);
    }
}

#[cfg(test)]
mod ledger_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct ChargedKey {
        id: u8,
        bytes: usize,
    }

    impl DeferredSelectionKeyCharge for ChargedKey {
        fn logical_retained_bytes(&self) -> usize {
            self.bytes
        }
    }

    #[derive(Debug)]
    struct CloneCountedKey {
        id: u8,
        bytes: usize,
    }

    static ACCEPTED_KEY_CLONES: AtomicUsize = AtomicUsize::new(0);
    static REJECTED_KEY_CLONES: AtomicUsize = AtomicUsize::new(0);

    impl Clone for CloneCountedKey {
        fn clone(&self) -> Self {
            match self.id {
                1 => &ACCEPTED_KEY_CLONES,
                2 => &REJECTED_KEY_CLONES,
                _ => panic!("unexpected clone-counted test key"),
            }
            .fetch_add(1, Ordering::SeqCst);
            Self {
                id: self.id,
                bytes: self.bytes,
            }
        }
    }

    impl PartialEq for CloneCountedKey {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for CloneCountedKey {}

    impl Hash for CloneCountedKey {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }

    impl DeferredSelectionKeyCharge for CloneCountedKey {
        fn logical_retained_bytes(&self) -> usize {
            self.bytes
        }
    }

    #[test]
    fn bounded_identity_tracking_marks_each_dropped_family_once() {
        let unicast = (Afi::Ipv4, Safi::Unicast);
        let flowspec = (Afi::Ipv4, Safi::FlowSpec);
        let mut identities = HashSet::new();
        let mut overflowed = HashSet::new();
        let mut bytes_by_family = HashMap::new();
        let mut retained_bytes = 0;
        let first = [
            ChargedKey { id: 1, bytes: 1 },
            ChargedKey { id: 1, bytes: 1 },
            ChargedKey { id: 2, bytes: 1 },
            ChargedKey { id: 3, bytes: 1 },
        ];

        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut identities,
            &mut overflowed,
            &mut bytes_by_family,
            &mut retained_bytes,
            first.iter().map(|key| (unicast, key)),
            0,
            DeferredSelectionLimits {
                identities: 2,
                retained_key_bytes: usize::MAX,
            },
        );
        assert_eq!(
            identities,
            HashSet::from([first[0].clone(), first[2].clone()])
        );
        assert_eq!(
            newly_overflowed,
            vec![(unicast, DeferredSelectionOverflowReason::Identities)]
        );
        assert_eq!(overflowed, HashSet::from([unicast]));
        assert_eq!(retained_bytes, 2);
        assert_eq!(bytes_by_family.get(&unicast), Some(&2));

        let current_len = identities.len();
        let second = [
            ChargedKey { id: 4, bytes: 1 },
            ChargedKey { id: 5, bytes: 1 },
            ChargedKey { id: 6, bytes: 1 },
        ];
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut identities,
            &mut overflowed,
            &mut bytes_by_family,
            &mut retained_bytes,
            [
                (unicast, &second[0]),
                (flowspec, &second[1]),
                (flowspec, &second[2]),
            ],
            current_len,
            DeferredSelectionLimits {
                identities: 2,
                retained_key_bytes: usize::MAX,
            },
        );
        assert_eq!(
            identities,
            HashSet::from([first[0].clone(), first[2].clone()])
        );
        assert_eq!(
            newly_overflowed,
            vec![(flowspec, DeferredSelectionOverflowReason::Identities)]
        );
        assert_eq!(overflowed, HashSet::from([unicast, flowspec]));
        assert_eq!(retained_bytes, 2);
    }

    #[test]
    fn simultaneous_identity_and_byte_exhaustion_records_the_combined_reason() {
        let unicast = (Afi::Ipv4, Safi::Unicast);
        let mut identities = HashSet::new();
        let mut overflowed = HashSet::new();
        let mut bytes_by_family = HashMap::new();
        let mut retained_bytes = 0;
        let first = ChargedKey { id: 1, bytes: 1 };
        let second = ChargedKey { id: 2, bytes: 1 };
        let limits = DeferredSelectionLimits {
            identities: 1,
            retained_key_bytes: 1,
        };

        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut identities,
            &mut overflowed,
            &mut bytes_by_family,
            &mut retained_bytes,
            [(unicast, &first), (unicast, &second)],
            0,
            limits,
        );
        assert_eq!(identities, HashSet::from([first]));
        assert_eq!(
            newly_overflowed,
            vec![(
                unicast,
                DeferredSelectionOverflowReason::IdentitiesAndLogicalBytes
            )],
            "with both budgets exhausted, neither single reason is truthful"
        );
    }

    #[test]
    fn logical_byte_limit_is_duplicate_free_sticky_and_saturating() {
        let unicast = (Afi::Ipv4, Safi::Unicast);
        let flowspec = (Afi::Ipv4, Safi::FlowSpec);
        let mut identities = HashSet::new();
        let mut overflowed = HashSet::new();
        let mut bytes_by_family = HashMap::new();
        let mut retained_bytes = 0;
        let first = ChargedKey { id: 1, bytes: 3 };
        let second = ChargedKey { id: 2, bytes: 2 };
        let dropped = ChargedKey { id: 3, bytes: 1 };
        let limits = DeferredSelectionLimits {
            identities: usize::MAX,
            retained_key_bytes: 5,
        };

        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut identities,
            &mut overflowed,
            &mut bytes_by_family,
            &mut retained_bytes,
            [
                (unicast, &first),
                (unicast, &first),
                (unicast, &second),
                (unicast, &dropped),
            ],
            0,
            limits,
        );
        assert_eq!(identities.len(), 2);
        assert_eq!(
            retained_bytes, 5,
            "duplicate delivery must not charge twice"
        );
        assert_eq!(bytes_by_family.get(&unicast), Some(&5));
        assert_eq!(
            newly_overflowed,
            vec![(unicast, DeferredSelectionOverflowReason::LogicalBytes)]
        );

        let huge = ChargedKey {
            id: 4,
            bytes: usize::MAX,
        };
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut identities,
            &mut overflowed,
            &mut bytes_by_family,
            &mut retained_bytes,
            [(flowspec, &huge)],
            2,
            DeferredSelectionLimits {
                identities: usize::MAX,
                retained_key_bytes: usize::MAX,
            },
        );
        assert_eq!(
            newly_overflowed,
            vec![(flowspec, DeferredSelectionOverflowReason::LogicalBytes)]
        );
        assert_eq!(retained_bytes, 5, "saturating admission must fail closed");
        assert!(!identities.contains(&huge));
    }

    #[test]
    fn byte_rejection_and_duplicate_at_cap_do_not_clone() {
        let family = (Afi::Ipv4, Safi::Unicast);
        ACCEPTED_KEY_CLONES.store(0, Ordering::SeqCst);
        REJECTED_KEY_CLONES.store(0, Ordering::SeqCst);
        let accepted = CloneCountedKey { id: 1, bytes: 1 };
        let rejected = CloneCountedKey { id: 2, bytes: 1 };
        let mut identities = HashSet::new();
        let mut overflowed = HashSet::new();
        let mut bytes_by_family = HashMap::new();
        let mut retained_bytes = 0;
        let limits = DeferredSelectionLimits {
            identities: usize::MAX,
            retained_key_bytes: 1,
        };

        assert!(
            DeferredSelectionKeys::extend_bounded(
                &mut identities,
                &mut overflowed,
                &mut bytes_by_family,
                &mut retained_bytes,
                [(family, &accepted)],
                0,
                limits,
            )
            .is_empty()
        );
        assert_eq!(ACCEPTED_KEY_CLONES.load(Ordering::SeqCst), 1);

        let current_len = identities.len();
        let newly_overflowed = DeferredSelectionKeys::extend_bounded(
            &mut identities,
            &mut overflowed,
            &mut bytes_by_family,
            &mut retained_bytes,
            [(family, &accepted), (family, &rejected)],
            current_len,
            limits,
        );
        assert_eq!(
            newly_overflowed,
            vec![(family, DeferredSelectionOverflowReason::LogicalBytes)]
        );
        assert_eq!(
            ACCEPTED_KEY_CLONES.load(Ordering::SeqCst),
            1,
            "duplicate-at-cap must be rejected by borrowed lookup without cloning"
        );
        assert_eq!(
            REJECTED_KEY_CLONES.load(Ordering::SeqCst),
            0,
            "byte-rejected candidates must not clone before admission"
        );
    }

    #[test]
    fn process_byte_budget_reclaims_by_family_only_after_complete_release() {
        let family_a = (Afi::Ipv4, Safi::Unicast);
        let family_b = (Afi::Ipv6, Safi::Unicast);
        let overflowed_family = (Afi::Ipv4, Safi::FlowSpec);
        let later_family = (Afi::L2Vpn, Safi::Evpn);
        let mut ledger = DeferredSelectionKeys::default();
        let charge = size_of::<rustbgpd_wire::Prefix>();
        ledger.limits = DeferredSelectionLimits {
            identities: usize::MAX,
            retained_key_bytes: charge * 2,
        };
        let keys = [
            rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                "192.0.2.0".parse().unwrap(),
                24,
            )),
            rustbgpd_wire::Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
                "2001:db8::".parse().unwrap(),
                64,
            )),
            rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                "198.51.100.0".parse().unwrap(),
                24,
            )),
            rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                "203.0.113.0".parse().unwrap(),
                24,
            )),
        ];
        let limits = ledger.limits;

        let current_len = ledger.len();
        let overflowed = DeferredSelectionKeys::extend_bounded(
            &mut ledger.unicast,
            &mut ledger.overflowed_families,
            &mut ledger.retained_key_bytes_by_family,
            &mut ledger.retained_key_bytes,
            [(family_a, &keys[0]), (family_b, &keys[1])],
            current_len,
            limits,
        );
        assert!(overflowed.is_empty());
        assert_eq!(ledger.retained_key_bytes, charge * 2);
        assert_eq!(
            ledger.retained_key_bytes_by_family.get(&family_a),
            Some(&charge)
        );
        assert_eq!(
            ledger.retained_key_bytes_by_family.get(&family_b),
            Some(&charge)
        );

        let current_len = ledger.len();
        let overflowed = DeferredSelectionKeys::extend_bounded(
            &mut ledger.unicast,
            &mut ledger.overflowed_families,
            &mut ledger.retained_key_bytes_by_family,
            &mut ledger.retained_key_bytes,
            [(overflowed_family, &keys[2])],
            current_len,
            limits,
        );
        assert_eq!(
            overflowed,
            vec![(
                overflowed_family,
                DeferredSelectionOverflowReason::LogicalBytes
            )]
        );

        assert!(ledger.unicast.remove(&keys[0]));
        assert_eq!(
            ledger.retained_key_bytes,
            charge * 2,
            "removing typed keys must not reclaim budget before complete family release"
        );
        ledger.complete_family_release(family_a);
        assert_eq!(ledger.retained_key_bytes, charge);
        assert!(!ledger.retained_key_bytes_by_family.contains_key(&family_a));

        let current_len = ledger.len();
        let overflowed = DeferredSelectionKeys::extend_bounded(
            &mut ledger.unicast,
            &mut ledger.overflowed_families,
            &mut ledger.retained_key_bytes_by_family,
            &mut ledger.retained_key_bytes,
            [(overflowed_family, &keys[2]), (later_family, &keys[3])],
            current_len,
            limits,
        );
        assert!(overflowed.is_empty());
        assert!(
            !ledger.unicast.contains(&keys[2]),
            "overflow remains sticky even after another family releases budget"
        );
        assert!(ledger.unicast.contains(&keys[3]));
        assert_eq!(ledger.retained_key_bytes, charge * 2);
        assert!(ledger.overflowed_families.contains(&overflowed_family));
    }

    #[test]
    fn nested_flowspec_and_bgpls_payloads_are_logically_charged() {
        let flowspec = crate::route::FlowSpecKey {
            afi: Afi::Ipv4,
            rule: rustbgpd_wire::FlowSpecRule {
                components: vec![
                    rustbgpd_wire::FlowSpecComponent::IpProtocol(vec![
                        rustbgpd_wire::NumericMatch {
                            end_of_list: true,
                            and_bit: false,
                            lt: false,
                            gt: false,
                            eq: true,
                            value: 6,
                        },
                    ]),
                    rustbgpd_wire::FlowSpecComponent::TcpFlags(vec![rustbgpd_wire::BitmaskMatch {
                        end_of_list: true,
                        and_bit: false,
                        not_bit: false,
                        match_bit: true,
                        value: 2,
                    }]),
                ],
            },
        };
        assert_eq!(
            flowspec.logical_retained_bytes(),
            size_of::<crate::route::FlowSpecKey>()
                + 2 * size_of::<rustbgpd_wire::FlowSpecComponent>()
                + size_of::<rustbgpd_wire::NumericMatch>()
                + size_of::<rustbgpd_wire::BitmaskMatch>()
        );

        let bgpls = crate::route::BgpLsRouteKey {
            family: crate::route::BgpLsFamily::LinkState,
            nlri: rustbgpd_wire::bgpls::BgpLsNlriKey {
                nlri_type: rustbgpd_wire::bgpls::BgpLsNlriType::Unknown(99),
                route_distinguisher: None,
                payload: bytes::Bytes::from_static(&[1, 2, 3, 4]),
            },
            path_id: 0,
        };
        assert_eq!(
            bgpls.logical_retained_bytes(),
            size_of::<crate::route::BgpLsRouteKey>() + 4
        );
    }
}
