//! RFC 4724 restarting-speaker route-selection deferral.
//!
//! The startup roster is frozen before the RIB actor starts.  A configured
//! peer only becomes a waiter after re-establishing a session. Dormant roster
//! entries do not hold selection or completion markers. `EoR` completion is
//! bound to the current classified session and the original startup deadline.

use crate::PeerId;
use crate::fast_hash::ShardedMap;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;
use std::mem::size_of;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Safi};

use super::RibManager;
use super::eor_hold::EorTrigger;
use super::evpn_recovery::EvpnCompleteFeed;

mod frozen_local;
pub(in crate::manager) use frozen_local::retained_route_bytes;
mod inventory;
mod rejections;
mod unicast_release;
pub(super) use inventory::UnicastReleaseInventory;
pub(super) use unicast_release::UnicastReleases;

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
    // Keep the per-family readback ledgers out of the RIB actor future.
    frozen_locals: Box<frozen_local::FrozenLocalRows>,
    unicast: BTreeSet<rustbgpd_wire::Prefix>,
    flowspec: ShardedMap<crate::route::FlowSpecKey, ()>,
    evpn: ShardedMap<rustbgpd_wire::EvpnRouteKey, ()>,
    vpn: ShardedMap<crate::route::VpnRibRouteKey, ()>,
    labeled: ShardedMap<crate::route::LabeledRibRouteKey, ()>,
    bgpls: ShardedMap<crate::route::BgpLsRouteKey, ()>,
    rtc: ShardedMap<crate::route::RtcRibRouteKey, ()>,
    /// Families for which at least one distinct identity could not be retained.
    /// Release enumerates that family's Loc-RIB keys as the fail-safe source
    /// for withdrawals already absent from Adj-RIB-In.
    overflowed_families: HashSet<(Afi, Safi)>,
    /// Logical retained-key bytes charged to each gated family. Charges stay
    /// owned until that family's complete release finishes.
    retained_key_bytes_by_family: HashMap<(Afi, Safi), usize>,
    /// O(1) process-wide sum of `retained_key_bytes_by_family`.
    retained_key_bytes: usize,
    /// Committed ledger keys have left the tree, but the active walk still
    /// reserves their bytes until it finishes or another waiter re-arms it.
    retired_unicast_bytes: [usize; 2],
    limits: DeferredSelectionLimits,
}

/// Both ledger layouts admit a distinct identity only after checking the
/// process budget. Unicast also needs an ordered seek across release turns.
trait DeferredKeySet<K> {
    fn contains(&self, key: &K) -> bool;
    fn admit(&mut self, key: K);
}

impl<K: Eq + Hash> DeferredKeySet<K> for ShardedMap<K, ()> {
    fn contains(&self, key: &K) -> bool {
        self.contains_key(key)
    }

    fn admit(&mut self, key: K) {
        self.insert(key, ());
    }
}

impl<K: Ord> DeferredKeySet<K> for BTreeSet<K> {
    fn contains(&self, key: &K) -> bool {
        BTreeSet::contains(self, key)
    }

    fn admit(&mut self, key: K) {
        self.insert(key);
    }
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

    #[cfg(any(test, feature = "bench-internals"))]
    pub(super) fn is_cleared(&self) -> bool {
        self.len() == 0
            && self.overflowed_families.is_empty()
            && self.retained_key_bytes_by_family.is_empty()
            && self.retained_key_bytes == 0
            && self.retired_unicast_bytes == [0; 2]
            && self.frozen_locals.is_cleared()
    }

    /// Insert distinct typed identities until the process-wide ledger limit is
    /// reached.  Returns each family that entered overflow fallback during
    /// this call; an already-overflowed family stops retaining further keys.
    fn extend_bounded<'a, T>(
        set: &mut impl DeferredKeySet<T>,
        overflowed_families: &mut HashSet<(Afi, Safi)>,
        retained_key_bytes_by_family: &mut HashMap<(Afi, Safi), usize>,
        retained_key_bytes: &mut usize,
        identities: impl IntoIterator<Item = ((Afi, Safi), &'a T)>,
        current_len: usize,
        limits: DeferredSelectionLimits,
    ) -> Vec<((Afi, Safi), DeferredSelectionOverflowReason)>
    where
        T: Clone + DeferredSelectionKeyCharge + 'a,
    {
        let mut remaining = limits.identities.saturating_sub(current_len);
        let mut newly_overflowed = Vec::new();
        for (family, identity) in identities {
            // Once a family is sticky-overflowed, skip even the borrowed key
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
            set.admit(identity.clone());
            remaining -= 1;
            *retained_key_bytes = retained_key_bytes.saturating_add(charge);
            let family_bytes = retained_key_bytes_by_family.entry(family).or_default();
            *family_bytes = family_bytes.saturating_add(charge);
        }
        newly_overflowed
    }

    fn cancel_unicast_release(&mut self, family: (Afi, Safi)) {
        debug_assert!(matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)));
        let retired =
            std::mem::take(&mut self.retired_unicast_bytes[usize::from(family.0 == Afi::Ipv6)]);
        if retired > 0 {
            let reserved = self
                .retained_key_bytes_by_family
                .get_mut(&family)
                .expect("retired keys retain their byte charge");
            *reserved -= retired;
            self.retained_key_bytes -= retired;
            if *reserved == 0 {
                self.retained_key_bytes_by_family.remove(&family);
            }
        }
    }

    fn complete_family_release(&mut self, family: (Afi, Safi), checkpoint: &mut impl FnMut()) {
        if matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)) {
            self.frozen_locals.clear_family(family.0, checkpoint);
            self.retired_unicast_bytes[usize::from(family.0 == Afi::Ipv6)] = 0;
        }
        self.overflowed_families.remove(&family);
        if let Some(released) = self.retained_key_bytes_by_family.remove(&family) {
            self.retained_key_bytes = self.retained_key_bytes.saturating_sub(released);
        }
    }
}

/// One family's release keys. A plain set that doubles rehashes every key
/// inside one checkpoint slice, about 20 ms at 262k EVPN keys. The split map
/// grows one shard at a time, and its exact distinct count then reserves the
/// set handed to selection before any key moves into it.
struct ReleaseKeys<K>(ShardedMap<K, ()>);

impl<K: Eq + Hash> ReleaseKeys<K> {
    fn new() -> Self {
        Self(ShardedMap::default())
    }

    fn insert(&mut self, key: K) {
        #[cfg(test)]
        let before = self.0.capacity();
        self.0.insert(key, ());
        #[cfg(test)]
        release_growth::record::<K>("staged", before, self.0.capacity());
    }

    fn extend(&mut self, keys: impl IntoIterator<Item = K>) {
        keys.into_iter().for_each(|key| self.insert(key));
    }

    fn into_set(mut self, checkpoint: &mut impl FnMut()) -> HashSet<K> {
        checkpoint();
        let mut keys = HashSet::with_capacity(self.0.len());
        checkpoint();
        for shard in self.0.shards_mut() {
            for (key, ()) in shard.drain() {
                checkpoint();
                #[cfg(test)]
                let before = keys.capacity();
                keys.insert(key);
                #[cfg(test)]
                release_growth::record::<K>("set", before, keys.capacity());
            }
            drop(std::mem::take(shard));
            checkpoint();
        }
        keys
    }
}

/// Test-only per-insert capacity growth of each release destination. Every
/// insert is bracketed by checkpoints, so one insert's growth is the rehash
/// work of one checkpoint slice.
#[cfg(test)]
pub(super) mod release_growth {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// `(key type, destination)` -> `(inserts, largest growth of one insert)`.
    pub(in crate::manager) type Growth = BTreeMap<(&'static str, &'static str), (usize, usize)>;

    thread_local! {
        static GROWTH: RefCell<Growth> = RefCell::default();
    }

    pub(super) fn record<K>(destination: &'static str, before: usize, after: usize) {
        GROWTH.with_borrow_mut(|growth| {
            let entry = growth
                .entry((std::any::type_name::<K>(), destination))
                .or_default();
            entry.0 += 1;
            entry.1 = entry.1.max(after.saturating_sub(before));
        });
    }

    pub(in crate::manager) fn take() -> Growth {
        GROWTH.take()
    }
}

use super::helpers::{afi_safi_label, gauge_val};

/// One peer in the startup-frozen RFC 4724 waiter roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionDeferralWaiterConfig {
    /// Configured neighbor: an addressed neighbor's startup handle, or an
    /// interface-only neighbor's interface, which binds to the first
    /// session learned on it (that neighbor keeps its handle across
    /// endpoints until configuration deletes it).
    pub peer: super::EorGraceTarget,
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
    UnclassifiedSession {
        session_id: u64,
    },
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
            Self::UnclassifiedSession { session_id } => ("awaiting_session", Some(session_id)),
            Self::AwaitingEor { session_id } => ("awaiting_eor", Some(session_id)),
            Self::AwaitingRefresh { session_id, .. } => ("awaiting_refresh", Some(session_id)),
            Self::Satisfied { session_id } => ("satisfied", Some(session_id)),
            Self::Excluded { session_id } => ("excluded", Some(session_id)),
        }
    }
}

#[derive(Debug)]
struct FamilyGate {
    waiters: HashMap<PeerId, WaiterState>,
    // The winning final trigger owns its cohort while the release spans turns.
    finishing: bool,
    selection_staged: bool,
    armed: bool,
}

#[derive(Debug)]
struct ReleasedFamily {
    reason: SelectionDeferralReleaseReason,
    waiters: HashMap<PeerId, WaiterState>,
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
    ambiguous_peers: HashSet<PeerId>,
    /// Interface-only roster entries whose neighbor has not yet had a
    /// session, with their families. Like any dormant entry they hold
    /// nothing until a session binds them.
    unbound_interfaces: HashMap<Arc<str>, Vec<(Afi, Safi)>>,
}

impl SelectionDeferral {
    fn blocking_waiters(gate: &FamilyGate) -> usize {
        gate.waiters
            .values()
            .filter(|state| {
                matches!(
                    state,
                    WaiterState::UnclassifiedSession { .. }
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
                    WaiterState::UnclassifiedSession { .. } | WaiterState::AwaitingEor { .. }
                )
            })
            .count()
    }

    pub(super) fn new(config: SelectionDeferralConfig, metrics: &BgpMetrics) -> Option<Self> {
        let mut active: HashMap<(Afi, Safi), FamilyGate> = HashMap::new();
        let mut seen = HashSet::new();
        let mut ambiguous_peers = HashSet::new();
        let mut unbound_interfaces: HashMap<Arc<str>, Vec<(Afi, Safi)>> = HashMap::new();
        for waiter in config.waiters {
            let peer = match waiter.peer {
                super::EorGraceTarget::Peer(peer) => {
                    if !seen.insert(peer) {
                        ambiguous_peers.insert(peer);
                    }
                    Some(peer)
                }
                super::EorGraceTarget::Interface(interface) => {
                    unbound_interfaces
                        .entry(interface)
                        .or_default()
                        .extend(waiter.families.iter().copied());
                    None
                }
            };
            for family in waiter.families {
                let gate = active.entry(family).or_insert_with(|| FamilyGate {
                    waiters: HashMap::new(),
                    finishing: false,
                    selection_staged: false,
                    armed: false,
                });
                if let Some(peer) = peer {
                    gate.waiters.insert(peer, WaiterState::AwaitingSession);
                }
            }
        }
        for peer in &ambiguous_peers {
            tracing::warn!(%peer, "duplicate static peer address in selection-deferral roster; an established session will wait for the timer because scoped identity is ambiguous");
        }
        if active.is_empty() || config.timeout.is_zero() {
            return None;
        }
        for (&(afi, safi), gate) in &active {
            let label = afi_safi_label(afi, safi);
            metrics.initialize_selection_deferral_failure_series(label);
            metrics.set_selection_deferral_active(label, false);
            metrics.set_selection_deferral_waiters(label, gauge_val(Self::blocking_waiters(gate)));
        }
        Some(Self {
            deadline: tokio::time::Instant::now() + config.timeout,
            active,
            released: HashMap::new(),
            ambiguous_peers,
            unbound_interfaces,
        })
    }

    /// Bind an interface-only roster entry to the first session learned on
    /// its interface. No other neighbor can be scoped to that interface
    /// (ADR-0142), and the neighbor keeps this handle for its lifetime.
    fn bind_interface(&mut self, peer: PeerId) {
        if self.unbound_interfaces.is_empty() {
            return;
        }
        let Some(families) = peer
            .interface()
            .and_then(|interface| self.unbound_interfaces.remove(&interface))
        else {
            return;
        };
        for family in families {
            if let Some(gate) = self.active.get_mut(&family).filter(|g| !g.finishing) {
                gate.waiters
                    .entry(peer)
                    .or_insert(WaiterState::AwaitingSession);
            }
        }
    }

    /// Configuration removed an interface-only neighbor: its roster entry
    /// ends whether or not a session bound it. A bound handle can outlive
    /// the stanza (a retired binding whose cleanup is still unconfirmed), so
    /// a later session of it must not re-arm the gate.
    pub(super) fn retire_interface(
        &mut self,
        interface: &str,
        metrics: &BgpMetrics,
    ) -> Vec<SelectionDeferralTransition> {
        self.unbound_interfaces.remove(interface);
        let bound: HashSet<PeerId> = self
            .active
            .values()
            .flat_map(|gate| gate.waiters.keys().copied())
            .filter(|peer| peer.interface().as_deref() == Some(interface))
            .collect();
        bound
            .into_iter()
            .flat_map(|peer| self.peer_deleted(peer, false, metrics))
            .collect()
    }

    pub(super) fn is_gated(&self, family: (Afi, Safi)) -> bool {
        self.active.get(&family).is_some_and(|gate| gate.armed)
    }

    /// Whether a family is still unreleased: its gate is armed, or a waiter
    /// can still arm it before the deadline.
    pub(super) fn may_hold(&self) -> bool {
        !self.active.is_empty()
    }

    /// [`Self::may_hold`] for one family.
    pub(super) fn may_hold_family(&self, family: (Afi, Safi)) -> bool {
        self.active.contains_key(&family)
    }

    pub(super) fn selection_deferred(&self, family: (Afi, Safi)) -> bool {
        self.active
            .get(&family)
            .is_some_and(|gate| gate.armed && !gate.selection_staged)
    }

    pub(super) fn has_deferred_selection(&self) -> bool {
        self.active
            .values()
            .any(|gate| gate.armed && !gate.selection_staged)
    }

    fn evaluate_family(
        &mut self,
        family: (Afi, Safi),
        release_reason: SelectionDeferralReleaseReason,
    ) -> Option<SelectionDeferralTransition> {
        let gate = self.active.get_mut(&family).filter(|g| !g.finishing)?;
        if !gate.armed {
            return None;
        }
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
        self.active
            .values()
            .any(|gate| !gate.finishing)
            .then_some(self.deadline)
    }

    pub(super) fn peer_snapshot(
        &self,
        peer: PeerId,
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
                active: gate.armed,
                waiter_state: waiter_state.to_string(),
                waiter_session_id,
                blocking_waiters: u64::try_from(Self::blocking_waiters(gate)).unwrap_or(u64::MAX),
                remaining_millis: if gate.armed { remaining_millis } else { 0 },
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
        peer: PeerId,
        session_id: u64,
        peer_restart_state: bool,
        peer_gr_families: &HashSet<(Afi, Safi)>,
        metrics: &BgpMetrics,
    ) -> Vec<SelectionDeferralTransition> {
        self.bind_interface(peer);
        if session_id == 0 || self.ambiguous_peers.contains(&peer) {
            self.unclassified_session(peer, session_id, metrics);
            return Vec::new();
        }
        let families: Vec<_> = self.active.keys().copied().collect();
        let mut transitions = Vec::new();
        for family in families {
            let Some(gate) = self.active.get_mut(&family).filter(|g| !g.finishing) else {
                continue;
            };
            if !gate.waiters.contains_key(&peer) {
                continue;
            }
            gate.armed = true;
            metrics.set_selection_deferral_active(afi_safi_label(family.0, family.1), true);
            if peer_restart_state || !peer_gr_families.contains(&family) {
                gate.waiters
                    .insert(peer, WaiterState::Excluded { session_id });
            } else {
                gate.selection_staged = false;
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

    /// An established session without trustworthy OPEN identity still waits;
    /// it must not be confused with a configured neighbor that never connected.
    pub(super) fn unclassified_session(
        &mut self,
        peer: PeerId,
        session_id: u64,
        metrics: &BgpMetrics,
    ) {
        self.bind_interface(peer);
        for (&family, gate) in self.active.iter_mut().filter(|(_, gate)| !gate.finishing) {
            if let Some(state) = gate.waiters.get_mut(&peer) {
                gate.armed = true;
                gate.selection_staged = false;
                *state = WaiterState::UnclassifiedSession { session_id };
                let label = afi_safi_label(family.0, family.1);
                metrics.set_selection_deferral_active(label, true);
                metrics
                    .set_selection_deferral_waiters(label, gauge_val(Self::blocking_waiters(gate)));
            }
        }
    }

    /// Re-evaluate after teardown and any collision-survivor registration have
    /// settled, so the last departed session cannot strand an active hold.
    fn settled_sessions(&mut self) -> Vec<SelectionDeferralTransition> {
        let families: Vec<_> = self.active.keys().copied().collect();
        families
            .into_iter()
            .filter_map(|family| {
                self.evaluate_family(family, SelectionDeferralReleaseReason::AllEndOfRib)
            })
            .collect()
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
    /// convergence-hold the family for the entire deferral window. A family
    /// transport never asks to refresh ([`requests_route_refresh`]) is
    /// excluded for the same reason.
    ///
    /// [`requests_route_refresh`]: crate::route::requests_route_refresh
    ///
    /// `Some` means at least one active family was classified; the contained
    /// transitions stage any family whose ordinary waiters are already done.
    /// `None` leaves every waiter unchanged.
    pub(super) fn await_collision_failback_refresh(
        &mut self,
        peer: PeerId,
        session_id: u64,
        peer_restart_state: bool,
        peer_gr_families: &HashSet<(Afi, Safi)>,
        peer_enhanced_refresh: bool,
        metrics: &BgpMetrics,
    ) -> Option<Vec<SelectionDeferralTransition>> {
        self.bind_interface(peer);
        if session_id == 0 || self.ambiguous_peers.contains(&peer) {
            self.unclassified_session(peer, session_id, metrics);
            return None;
        }

        let families: Vec<_> = self.active.keys().copied().collect();
        let mut classified = false;
        let mut transitions = Vec::new();
        for family in families {
            let Some(gate) = self.active.get_mut(&family).filter(|g| !g.finishing) else {
                continue;
            };
            if gate.waiters.get(&peer) != Some(&WaiterState::AwaitingSession) {
                continue;
            }
            gate.armed = true;
            metrics.set_selection_deferral_active(afi_safi_label(family.0, family.1), true);
            let state = if peer_restart_state
                || !peer_gr_families.contains(&family)
                || !peer_enhanced_refresh
                || !crate::route::requests_route_refresh(family)
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

    /// Remove a departed current session from the blocking cohort. Release
    /// waits until teardown or collision-survivor registration has settled.
    pub(super) fn session_down(&mut self, peer: PeerId, session_id: u64, metrics: &BgpMetrics) {
        for (&family, gate) in self.active.iter_mut().filter(|(_, gate)| !gate.finishing) {
            if matches!(
                gate.waiters.get(&peer),
                Some(
                    WaiterState::UnclassifiedSession { session_id: current }
                        | WaiterState::AwaitingEor { session_id: current }
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
    /// neighbor, so no future session can join its current cohort. Unlike
    /// `session_down` (which settles after teardown or failback), deletion
    /// is authoritative — any family whose remaining waiters are already
    /// done completes here instead of blocking until the timer. An
    /// ambiguous roster address stays fail-closed: address-only identity
    /// cannot tell which of the duplicate configured peers was deleted.
    /// A retired interface-only binding (`keep_series`) is not a deletion:
    /// the neighbor keeps its handle and roster entry, and only its departed
    /// session stops blocking.
    pub(super) fn peer_deleted(
        &mut self,
        peer: PeerId,
        keep_series: bool,
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
            let Some(gate) = self.active.get_mut(&family).filter(|g| !g.finishing) else {
                continue;
            };
            let present = if keep_series {
                gate.waiters
                    .get_mut(&peer)
                    .map(|state| *state = WaiterState::AwaitingSession)
                    .is_some()
            } else {
                gate.waiters.remove(&peer).is_some()
            };
            if !present {
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
        peer: PeerId,
        session_id: u64,
        family: (Afi, Safi),
        metrics: &BgpMetrics,
    ) -> Option<SelectionDeferralTransition> {
        if session_id == 0 {
            return None;
        }
        let gate = self.active.get_mut(&family).filter(|g| !g.finishing)?;
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
        peer: PeerId,
        session_id: u64,
        family: (Afi, Safi),
    ) -> Option<SelectionDeferralTransition> {
        let gate = self.active.get_mut(&family).filter(|g| !g.finishing)?;
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
        peer: PeerId,
        session_id: u64,
        family: (Afi, Safi),
        metrics: &BgpMetrics,
    ) -> Option<SelectionDeferralTransition> {
        let gate = self.active.get_mut(&family).filter(|g| !g.finishing)?;
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

    pub(super) fn expire(&self) -> Vec<SelectionDeferralTransition> {
        self.active
            .iter()
            .filter(|(_, gate)| !gate.finishing)
            .map(|(&family, gate)| SelectionDeferralTransition::Release {
                family,
                // Timer fallback rebuilds the complete family even after collision staging.
                already_staged: false,
                release_reason: if gate.armed {
                    SelectionDeferralReleaseReason::TimerExpired
                } else {
                    SelectionDeferralReleaseReason::AllExcluded
                },
            })
            .collect()
    }

    /// A release selects the family before it ends the gate: selection is
    /// no longer deferred, convergence (and the family's End-of-RIB) still
    /// is, exactly as after a `Stage` transition.
    fn stage_for_release(&mut self, family: (Afi, Safi)) {
        if let Some(gate) = self.active.get_mut(&family) {
            gate.selection_staged = true;
        }
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
        self.selection_deferred_any()
    }

    /// An empty input retains nothing, so it opens no readiness owner.
    fn with_deferred_selection_recording<T>(
        &mut self,
        affected: &HashSet<T>,
        work: impl FnOnce(&mut Self),
    ) {
        if affected.is_empty() || !self.deferred_selection_recording_active() {
            return;
        }
        super::with_executor_handoff(|| self.with_replacement_readiness(work));
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
        self.invalidate_release_selection(affected);
        self.with_deferred_selection_recording(affected, |manager| {
            manager
                .record_deferred_unicast_bounded(affected, manager.deferred_selection_keys.limits);
        });
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
        let readiness = self.replacement_readiness.clone();
        let deferred = affected
            .iter()
            .inspect(|_| {
                super::replacement_readiness_checkpoint_at(
                    &readiness,
                    "selection_record_unicast",
                    false,
                );
            })
            .filter_map(|prefix| {
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
        self.with_deferred_selection_recording(affected, |manager| {
            let Some(selection) = manager
                .selection_deferral
                .as_ref()
                .filter(|selection| selection.has_deferred_selection())
            else {
                return;
            };
            let readiness = manager.replacement_readiness.clone();
            let deferred = affected
                .iter()
                .inspect(|_| {
                    super::replacement_readiness_checkpoint_at(
                        &readiness,
                        "selection_record_flowspec",
                        false,
                    );
                })
                .filter_map(|key| {
                    let family = key.family();
                    selection
                        .selection_deferred(family)
                        .then_some((family, key))
                });
            let current_len = manager.deferred_selection_keys.len();
            let limits = manager.deferred_selection_keys.limits;
            let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                &mut manager.deferred_selection_keys.flowspec,
                &mut manager.deferred_selection_keys.overflowed_families,
                &mut manager.deferred_selection_keys.retained_key_bytes_by_family,
                &mut manager.deferred_selection_keys.retained_key_bytes,
                deferred,
                current_len,
                limits,
            );
            manager.record_selection_ledger_overflows(newly_overflowed);
        });
    }

    pub(super) fn record_deferred_evpn(&mut self, affected: &HashSet<rustbgpd_wire::EvpnRouteKey>) {
        self.with_deferred_selection_recording(affected, |manager| {
            if manager.selection_deferred((Afi::L2Vpn, Safi::Evpn)) {
                let readiness = manager.replacement_readiness.clone();
                let deferred = affected
                    .iter()
                    .inspect(|_| {
                        super::replacement_readiness_checkpoint_at(
                            &readiness,
                            "selection_record_evpn",
                            false,
                        );
                    })
                    .map(|key| ((Afi::L2Vpn, Safi::Evpn), key));
                let current_len = manager.deferred_selection_keys.len();
                let limits = manager.deferred_selection_keys.limits;
                let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                    &mut manager.deferred_selection_keys.evpn,
                    &mut manager.deferred_selection_keys.overflowed_families,
                    &mut manager.deferred_selection_keys.retained_key_bytes_by_family,
                    &mut manager.deferred_selection_keys.retained_key_bytes,
                    deferred,
                    current_len,
                    limits,
                );
                manager.record_selection_ledger_overflows(newly_overflowed);
            }
        });
    }

    pub(super) fn record_deferred_vpn(&mut self, affected: &HashSet<crate::route::VpnRibRouteKey>) {
        self.with_deferred_selection_recording(affected, |manager| {
            let Some(selection) = manager
                .selection_deferral
                .as_ref()
                .filter(|selection| selection.has_deferred_selection())
            else {
                return;
            };
            let readiness = manager.replacement_readiness.clone();
            let deferred = affected
                .iter()
                .inspect(|_| {
                    super::replacement_readiness_checkpoint_at(
                        &readiness,
                        "selection_record_vpn",
                        false,
                    );
                })
                .filter_map(|key| {
                    let family = key.afi_safi();
                    selection
                        .selection_deferred(family)
                        .then_some((family, key))
                });
            let current_len = manager.deferred_selection_keys.len();
            let limits = manager.deferred_selection_keys.limits;
            let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                &mut manager.deferred_selection_keys.vpn,
                &mut manager.deferred_selection_keys.overflowed_families,
                &mut manager.deferred_selection_keys.retained_key_bytes_by_family,
                &mut manager.deferred_selection_keys.retained_key_bytes,
                deferred,
                current_len,
                limits,
            );
            manager.record_selection_ledger_overflows(newly_overflowed);
        });
    }

    pub(super) fn record_deferred_labeled(
        &mut self,
        affected: &HashSet<crate::route::LabeledRibRouteKey>,
    ) {
        self.with_deferred_selection_recording(affected, |manager| {
            let Some(selection) = manager
                .selection_deferral
                .as_ref()
                .filter(|selection| selection.has_deferred_selection())
            else {
                return;
            };
            let readiness = manager.replacement_readiness.clone();
            let deferred = affected
                .iter()
                .inspect(|_| {
                    super::replacement_readiness_checkpoint_at(
                        &readiness,
                        "selection_record_labeled",
                        false,
                    );
                })
                .filter_map(|key| {
                    let family = key.afi_safi();
                    selection
                        .selection_deferred(family)
                        .then_some((family, key))
                });
            let current_len = manager.deferred_selection_keys.len();
            let limits = manager.deferred_selection_keys.limits;
            let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                &mut manager.deferred_selection_keys.labeled,
                &mut manager.deferred_selection_keys.overflowed_families,
                &mut manager.deferred_selection_keys.retained_key_bytes_by_family,
                &mut manager.deferred_selection_keys.retained_key_bytes,
                deferred,
                current_len,
                limits,
            );
            manager.record_selection_ledger_overflows(newly_overflowed);
        });
    }

    pub(super) fn record_deferred_bgpls(
        &mut self,
        affected: &HashSet<crate::route::BgpLsRouteKey>,
    ) {
        self.with_deferred_selection_recording(affected, |manager| {
            let Some(selection) = manager
                .selection_deferral
                .as_ref()
                .filter(|selection| selection.has_deferred_selection())
            else {
                return;
            };
            let readiness = manager.replacement_readiness.clone();
            let deferred = affected
                .iter()
                .inspect(|_| {
                    super::replacement_readiness_checkpoint_at(
                        &readiness,
                        "selection_record_bgpls",
                        false,
                    );
                })
                .filter_map(|key| {
                    let family = key.family.to_afi_safi();
                    selection
                        .selection_deferred(family)
                        .then_some((family, key))
                });
            let current_len = manager.deferred_selection_keys.len();
            let limits = manager.deferred_selection_keys.limits;
            let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                &mut manager.deferred_selection_keys.bgpls,
                &mut manager.deferred_selection_keys.overflowed_families,
                &mut manager.deferred_selection_keys.retained_key_bytes_by_family,
                &mut manager.deferred_selection_keys.retained_key_bytes,
                deferred,
                current_len,
                limits,
            );
            manager.record_selection_ledger_overflows(newly_overflowed);
        });
    }

    pub(super) fn record_deferred_rtc(&mut self, affected: &HashSet<crate::route::RtcRibRouteKey>) {
        self.with_deferred_selection_recording(affected, |manager| {
            if manager.selection_deferred(crate::route::RtcRibRouteKey::afi_safi()) {
                let family = crate::route::RtcRibRouteKey::afi_safi();
                let readiness = manager.replacement_readiness.clone();
                let deferred = affected
                    .iter()
                    .inspect(|_| {
                        super::replacement_readiness_checkpoint_at(
                            &readiness,
                            "selection_record_rtc",
                            false,
                        );
                    })
                    .map(|key| (family, key));
                let current_len = manager.deferred_selection_keys.len();
                let limits = manager.deferred_selection_keys.limits;
                let newly_overflowed = DeferredSelectionKeys::extend_bounded(
                    &mut manager.deferred_selection_keys.rtc,
                    &mut manager.deferred_selection_keys.overflowed_families,
                    &mut manager.deferred_selection_keys.retained_key_bytes_by_family,
                    &mut manager.deferred_selection_keys.retained_key_bytes,
                    deferred,
                    current_len,
                    limits,
                );
                manager.record_selection_ledger_overflows(newly_overflowed);
            }
        });
    }

    #[cfg(test)]
    pub(in crate::manager) fn record_deferred_unicast_with_test_limit(
        &mut self,
        affected: &HashSet<rustbgpd_wire::Prefix>,
        limit: usize,
    ) {
        self.with_deferred_selection_recording(affected, |manager| {
            manager.record_deferred_unicast_bounded(
                affected,
                DeferredSelectionLimits {
                    identities: limit,
                    retained_key_bytes: MAX_DEFERRED_SELECTION_RETAINED_KEY_BYTES,
                },
            );
        });
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

    #[cfg(test)]
    pub(in crate::manager) fn deferred_selection_storage_shape_for_test(
        &self,
        family: (Afi, Safi),
    ) -> (usize, usize) {
        let keys = &self.deferred_selection_keys;
        match family.1 {
            // The ordered tree has no reserved bucket array.
            Safi::Unicast => (keys.unicast.len(), 0),
            Safi::FlowSpec => (keys.flowspec.len(), keys.flowspec.capacity()),
            Safi::Evpn => (keys.evpn.len(), keys.evpn.capacity()),
            Safi::MplsVpn => (keys.vpn.len(), keys.vpn.capacity()),
            Safi::LabeledUnicast => (keys.labeled.len(), keys.labeled.capacity()),
            Safi::BgpLs | Safi::BgpLsVpn => (keys.bgpls.len(), keys.bgpls.capacity()),
            Safi::RtConstrain => (keys.rtc.len(), keys.rtc.capacity()),
            _ => unreachable!("test uses a supported ledger family"),
        }
    }

    /// Consume a current-session `EoR` in the startup gate. The caller invokes
    /// the ordinary GR/LLGR `EoR` handler after this, then recomputes the released
    /// family against the complete Adj-RIB-In cohort.
    pub(super) fn selection_deferral_end_of_rib(
        &mut self,
        peer: PeerId,
        session_id: u64,
        family: (Afi, Safi),
    ) -> Option<SelectionDeferralTransition> {
        self.selection_deferral
            .as_mut()
            .and_then(|selection| selection.end_of_rib(peer, session_id, family, &self.metrics))
    }

    pub(super) fn selection_deferral_begin_route_refresh(
        &mut self,
        peer: PeerId,
        session_id: u64,
        family: (Afi, Safi),
    ) -> Option<SelectionDeferralTransition> {
        self.selection_deferral
            .as_mut()
            .and_then(|selection| selection.begin_route_refresh(peer, session_id, family))
    }

    pub(super) fn selection_deferral_end_route_refresh(
        &mut self,
        peer: PeerId,
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
            .as_ref()
            .map_or_else(Vec::new, SelectionDeferral::expire);
        self.apply_selection_deferral_transitions(families, "Selection_Deferral_Timer expired");
    }

    pub(super) fn deferred_selection_families(&self) -> HashSet<(Afi, Safi)> {
        self.selection_deferral
            .as_ref()
            .map_or_else(HashSet::new, |selection| {
                selection
                    .active
                    .keys()
                    .copied()
                    .filter(|family| selection.selection_deferred(*family))
                    .collect()
            })
    }

    pub(super) fn reselect_newly_deferred_local(&mut self, previous: &HashSet<(Afi, Safi)>) {
        let families: HashSet<_> = self
            .deferred_selection_families()
            .difference(previous)
            .copied()
            .collect();
        if families.is_empty() {
            return;
        }
        self.with_selection_readiness(|manager| {
            for &family in &families {
                manager.cancel_rearmed_release(family);
            }
            manager.suspend_conditional_advertisement_families(&families);
            manager.retain_selection_group_admission(&families);
            let readiness = manager.replacement_readiness.clone();
            let mut checkpoint =
                || super::replacement_readiness_checkpoint_at(&readiness, "selection_arm", false);
            let mut prefixes: HashSet<_> = manager
                .ribs
                .get(&super::helpers::LOCAL_PEER)
                .into_iter()
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_slots)
                .inspect(|_| checkpoint())
                .flatten()
                .filter(|route| families.contains(&super::helpers::prefix_family(&route.prefix)))
                .map(|route| route.prefix)
                .collect();
            if !prefixes.is_empty() {
                manager.advance_all_route_pages();
                let mut changed = manager.recompute_best(&prefixes);
                manager.distribute_changes(&changed, &prefixes);
                super::retire_hash_set(&mut changed, &mut checkpoint);
            }
            super::retire_hash_set(&mut prefixes, &mut checkpoint);
            let mut flowspec: HashSet<_> = manager
                .ribs
                .get(&super::helpers::LOCAL_PEER)
                .into_iter()
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_flowspec)
                .inspect(|_| checkpoint())
                .filter(|route| families.contains(&route.family()))
                .map(crate::route::FlowSpecRoute::selection_key)
                .collect();
            if !flowspec.is_empty() {
                manager.advance_all_route_pages();
                manager.recompute_and_distribute_flowspec(&flowspec);
            }
            super::retire_hash_set(&mut flowspec, &mut checkpoint);
        });
    }

    pub(super) fn settle_selection_sessions(&mut self) {
        let transitions = self
            .selection_deferral
            .as_mut()
            .map_or_else(Vec::new, SelectionDeferral::settled_sessions);
        self.apply_selection_deferral_transitions(
            transitions,
            "established session cohort settled",
        );
    }

    pub(super) fn next_selection_deferral_deadline(&self) -> Option<tokio::time::Instant> {
        self.selection_deferral
            .as_ref()
            .and_then(SelectionDeferral::deadline)
    }

    pub(super) fn apply_selection_deferral_transitions(
        &mut self,
        transitions: impl IntoIterator<Item = SelectionDeferralTransition>,
        reason: &'static str,
    ) {
        let mut transitions = transitions.into_iter().peekable();
        if transitions.peek().is_none() {
            return;
        }
        self.with_selection_readiness(|manager| {
        let mut released = false;
        for transition in transitions {
            let idle = !manager.unicast_release_runnable();
            if manager.start_unicast_release(transition, reason) {
                if idle {
                    manager.finish_small_unicast_release();
                }
                continue;
            }
            match transition {
                SelectionDeferralTransition::Stage { family } => {
                    tracing::info!(
                        afi = ?family.0,
                        safi = ?family.1,
                        reason,
                        "RFC 4724 route selection staged while collision-failback convergence remains held"
                    );
                    manager.recompute_released_selection_family(family, true);
                    released |= family == crate::route::RtcRibRouteKey::afi_safi();
                }
                SelectionDeferralTransition::Release {
                    family,
                    already_staged,
                    release_reason,
                } => {
                    let armed = manager.selection_convergence_held(family);
                    let mut resynced = HashSet::new();
                    if armed && !already_staged {
                        // The family's routes are selected and sent while
                        // its gate is still armed, as on the staged path:
                        // the gate holds the family's End-of-RIB until
                        // they are admitted, whichever pass, resync or
                        // owed-key event runs in between.
                        if let Some(selection) = manager.selection_deferral.as_mut() {
                            selection.stage_for_release(family);
                        }
                        resynced = manager.recompute_released_selection_family(family, false);
                    }
                    if let Some(selection) = manager.selection_deferral.as_mut() {
                        selection.release(family, release_reason, &manager.metrics);
                        manager.update_selection_inventory_index();
                        manager.retire_release_peers_if_idle();
                    }
                    if armed {
                        manager.complete_selection_family(family, resynced, reason);
                        released = true;
                    }
                }
            }
        }
        if released {
            manager.service_selection_marker_releases(super::RESYNC_PEERS_PER_TICK);
        }
        });
        // A family released before it ever armed skips the completion, so
        // retire what no held End-of-RIB can still need here too.
        self.request_helper_stale_retire();
    }

    pub(super) fn selection_peer_convergence_held(
        &self,
        peer: PeerId,
        family: (Afi, Safi),
    ) -> bool {
        self.selection_convergence_held(family)
            || self.eor.release_pending(peer, family)
            || self.release_marker_pending(peer, family)
            || self.late_release_join_pending(peer, family)
    }

    /// The dirty ring owns a deferred forced resync too. A sibling gate's
    /// earlier partial resync did not cover the rows about to be selected.
    pub(super) fn wake_unicast_release_resync(&mut self, peer: PeerId, family: (Afi, Safi)) {
        if self
            .peer_sendable_families
            .get(&peer)
            .is_some_and(|families| families.contains(&family))
        {
            if self.force_outbound_peers.contains(&peer) && !self.dirty_peers.contains(&peer) {
                self.mark_outbound_dirty(peer);
            } else if self.dirty_peers.contains(&peer) {
                self.set_selection_partial_caught_up(peer, false);
            }
        }
    }

    /// Complete one current registration after the producer has sealed. Clean
    /// member rows were admitted in the release batches; private cursors and
    /// dirty/forced peers retain their own table-before-marker obligations.
    pub(super) fn finish_unicast_release_peer(&mut self, peer: PeerId, family: (Afi, Safi)) {
        self.refresh_eor_retry(peer);
        let owed_marker = self.eor.owes(peer, family);
        if self.force_outbound_peers.contains(&peer)
            && !self.dirty_peers.contains(&peer)
            && !self.selection_partial_caught_up(peer)
        {
            // A force may have arrived after this peer's enrollment.
            self.mark_outbound_dirty(peer);
        }
        let missing_group_rows_admitted = self.take_release_missing_admitted(peer, family);
        if owed_marker {
            self.settle_unicast_release_eor(peer, family, missing_group_rows_admitted);
            if self.dirty_peers.contains(&peer)
                && self.selection_partial_caught_up(peer)
                && self.owes(peer, family)
                && self.eor_resync_ready(peer).contains(&family)
            {
                self.set_selection_partial_caught_up(peer, false);
            }
        }
        if self.take_selection_refresh(peer, family) {
            self.defer_refresh_answer(peer, family, owed_marker);
        }
        // Peers without an owed marker, including a source-suppressed group
        // member, can also own startup admission proof.
        if self.retain_initial_group_admitted(peer)
            && !self.late_release_join_pending(peer, family)
            && !self.dirty_peers.contains(&peer)
            && !self.force_outbound_peers.contains(&peer)
            && !self.selection_resync_held(peer)
        {
            self.complete_initial_selection_replay(peer);
            self.retire_completed_initial_group_admitted(peer);
        }
    }

    /// Finish the release of `family`, whose routes were selected under the
    /// armed gate. `resynced` names the peers whose pending resync that
    /// pass admitted.
    fn complete_selection_family(
        &mut self,
        family: (Afi, Safi),
        resynced: HashSet<PeerId>,
        reason: &'static str,
    ) {
        self.replacement_checkpoint_at("selection_inventory", false);
        // Release does not by itself purge the stale rows a GR helper keeps:
        // our End-of-RIB does, once it is sent, and replay grace can still
        // hold it. A carry stays while that End-of-RIB can be held and its
        // session has not sent it; deleted exempt keys are withdrawn while
        // it is held.
        self.request_helper_stale_retire();
        tracing::info!(
            afi = ?family.0,
            safi = ?family.1,
            reason,
            "RFC 4724 route-selection deferral released"
        );
        self.eor.begin_family_release(
            family,
            resynced,
            self.selection_deferred_refresh.contains_key(&family),
        );
        // Only a VPN or unicast gate can have held the grouped initial
        // admission proof. Unicast owns its own release frontier.
        if matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::MplsVpn)) {
            self.retire_settled_selection_admission();
        }
    }

    /// The current registration has reached the front of this family's
    /// release. Replay missing rows before its marker and answer a held
    /// refresh without duplicating the genuine convergence marker.
    pub(super) fn finish_selection_marker_peer(
        &mut self,
        family: (Afi, Safi),
        peer: PeerId,
        was_resynced: bool,
        owed_at_release: bool,
    ) {
        self.refresh_eor_retry(peer);
        if self.outbound_channel_gone(peer) {
            if self.take_selection_refresh(peer, family)
                && self.refresh_waits_for_registration(peer)
            {
                // A live session can request a refresh before its sender
                // is installed. Its registration will wake the pending reply.
                self.defer_refresh_answer(peer, family, owed_at_release);
            }
            return;
        }
        if owed_at_release && self.eor.owes(peer, family) {
            self.finish_selection_marker_table(peer, family, was_resynced);
        }
        self.finish_selection_refresh(peer, family, owed_at_release);
        if self.retain_initial_group_admitted(peer)
            && !self.dirty_peers.contains(&peer)
            && !self.force_outbound_peers.contains(&peer)
            && !self.selection_resync_held(peer)
        {
            self.complete_initial_selection_replay(peer);
            self.retire_completed_initial_group_admitted(peer);
        }
    }

    fn finish_selection_marker_table(
        &mut self,
        peer: PeerId,
        family: (Afi, Safi),
        was_resynced: bool,
    ) {
        // Keep this decision across admission: a successful terminal can
        // retire a private-handoff receipt inside the same call.
        let evpn_coverage_required = family == (Afi::L2Vpn, Safi::Evpn)
            && (self.evpn_grouped_member_of(peer).is_some() || self.has_private_evpn_handoff(peer));
        if evpn_coverage_required {
            let (feed, private_resync) = self.prepare_selection_evpn_feed(peer);
            if feed.is_some() || private_resync {
                self.distribute_selection_marker_feed(peer, feed);
            }
        }
        // A later missed delta invalidates the release-time resync. A
        // sibling gate may still own dirty/forced work whose open families
        // were already admitted by an earlier stage.
        if !self.resync_pending(peer)
            && (was_resynced
                || self.dirty_peers.contains(&peer)
                || self.force_outbound_peers.contains(&peer))
        {
            self.settle_eor_behind_resync(peer);
            if self.dirty_peers.contains(&peer) && self.eor_resync_ready(peer).contains(&family) {
                self.set_selection_partial_caught_up(peer, false);
            }
            return;
        }
        if self.force_outbound_peers.contains(&peer) && !self.dirty_peers.contains(&peer) {
            self.mark_outbound_dirty(peer);
        }
        if self.dirty_peers.contains(&peer) {
            return;
        }
        if !evpn_coverage_required {
            use super::route_refresh::{FamilyReplayKind, FamilyReplayOutcome};
            match self.send_route_refresh_response_inner(
                peer,
                family.0,
                family.1,
                FamilyReplayKind::SelectionRelease,
            ) {
                FamilyReplayOutcome::Failed => {
                    self.mark_outbound_dirty(peer);
                    return;
                }
                FamilyReplayOutcome::NoReleaseRows => {
                    self.settle_free_family_eor(peer, family, None);
                    return;
                }
                FamilyReplayOutcome::Committed | FamilyReplayOutcome::Deferred => {}
            }
        }
        self.settle_eor_of(peer, &[family], EorTrigger::Release);
    }

    fn finish_selection_refresh(&mut self, peer: PeerId, family: (Afi, Safi), suppress_eor: bool) {
        if !self.take_selection_refresh(peer, family) {
            return;
        }
        if self.dirty_peers.contains(&peer) {
            self.defer_refresh_answer(peer, family, suppress_eor);
        } else {
            let _ = self.send_route_refresh_response_inner(
                peer,
                family.0,
                family.1,
                super::route_refresh::FamilyReplayKind::PeerRefresh { suppress_eor },
            );
        }
    }

    /// Owe `family` whole to every receiver that holds it in its own
    /// Adj-RIB-Out, is not dirty or forced (a resync covers those) and is
    /// not waiting for the peer's first refresh behind an ORF gate.
    fn owe_released_family(&mut self, family: (Afi, Safi)) {
        let Some(owed) = super::outbound_owing::OwedFamily::of(family) else {
            return;
        };
        let peers: Vec<PeerId> = self
            .peer_sendable_families
            .iter()
            .inspect(|_| self.replacement_checkpoint(false))
            .filter(|(_, families)| families.contains(&family))
            .map(|(&peer, _)| peer)
            .collect();
        for peer in peers {
            self.replacement_checkpoint(false);
            // An RFC 5291 gate withholds the family until the peer's first
            // refresh, whose answer is the whole table: nothing is owed
            // before it, and a debt the gate cannot drain would hold the
            // marker of a peer that never refreshes.
            let orf_gated = self
                .peer_orf_pending
                .get(&peer)
                .is_some_and(|gated| gated.contains(&family));
            if !orf_gated
                && self.owing_peer_in_scope(peer)
                && self.owing_family_in_scope(peer, owed)
            {
                self.owe_whole_family(peer, owed);
            }
        }
    }

    /// Pending peers wait until release has updated both selection and the
    /// shared group tables; their existing resync obligation covers the delta.
    pub(super) fn selection_release_resync_pending(&self, peer: PeerId) -> bool {
        (self.selection_release_staging.is_some() || self.release_resync_waits(peer))
            && (self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer))
    }

    /// Admit one empty resync pass while the selection gate still holds `EoR`.
    /// The returned peers need only their marker when that gate releases.
    fn run_released_selection_resyncs(
        &mut self,
        family: (Afi, Safi),
        mut targets: HashSet<PeerId>,
        feeds: HashMap<PeerId, EvpnCompleteFeed>,
    ) -> HashSet<PeerId> {
        let mut pending = HashSet::new();
        for &peer in self.dirty_peers.iter().chain(&self.force_outbound_peers) {
            self.replacement_checkpoint(false);
            if self.resync_pending(peer)
                && (targets.contains(&peer)
                    || self
                        .peer_sendable_families
                        .get(&peer)
                        .is_some_and(|f| f.contains(&family)))
            {
                targets.insert(peer);
                if self.eor.owes(peer, family) {
                    pending.insert(peer);
                }
            }
        }
        targets.extend(feeds.keys().copied());
        if !targets.is_empty() {
            self.distribute_scoped_resync(targets, feeds, false);
            pending.retain(|&peer| {
                self.replacement_checkpoint(false);
                !self.resync_pending(peer)
            });
        }
        pending
    }

    /// Preserve the admitted projection before selected EVPN rows advance
    /// group tables. Empty inventory needs no pre-mutation capture.
    fn capture_selection_evpn_before_stage(&mut self) {
        let family = (Afi::L2Vpn, Safi::Evpn);
        let peers: Vec<_> = self
            .eor
            .peers_for_family(family)
            .inspect(|_| {
                self.replacement_checkpoint(false);
                #[cfg(test)]
                self.observe_marker_candidate();
            })
            .filter(|peer| {
                self.peer_sendable_families
                    .get(peer)
                    .is_some_and(|families| families.contains(&family))
                    && self.evpn_grouped_member_of(*peer).is_some()
            })
            .collect();
        for peer in peers {
            self.replacement_checkpoint(false);
            self.capture_clean_evpn_before_dirty(peer);
        }
    }

    /// Prepare coverage under the staging gate before its table pass.
    fn prepare_selection_evpn_feeds(&mut self) -> HashMap<PeerId, EvpnCompleteFeed> {
        let family = (Afi::L2Vpn, Safi::Evpn);
        if self.selection_deferred(family) {
            return HashMap::new();
        }
        let peers: Vec<_> = self
            .eor
            .peers_for_family(family)
            .inspect(|_| {
                self.replacement_checkpoint(false);
                #[cfg(test)]
                self.observe_marker_candidate();
            })
            .collect();
        let mut feeds = HashMap::new();
        for peer in peers {
            self.replacement_checkpoint(false);
            if let (Some(feed), _) = self.prepare_selection_evpn_feed(peer) {
                feeds.insert(peer, feed);
            }
        }
        feeds
    }

    /// A release of unchanged inventory may still need a complete feed.
    /// Only a peer with missing coverage needs a table pass.
    fn prepare_selection_evpn_feed(&mut self, peer: PeerId) -> (Option<EvpnCompleteFeed>, bool) {
        if self.dirty_peers.contains(&peer)
            || self.force_outbound_peers.contains(&peer)
            || self.evpn_feed_is_current(peer)
            || self.evpn_recovery_reset_pending(peer)
        {
            return (None, false);
        }
        if let Some(gid) = self.evpn_grouped_member_of(peer) {
            if self
                .peer_sendable_families
                .get(&peer)
                .is_some_and(|families| families.contains(&(Afi::L2Vpn, Safi::Evpn)))
            {
                self.capture_clean_evpn_before_dirty(peer);
            }
            if self.complete_feed_deferred(peer) {
                return (None, false);
            }
            if let Some(feed) = self.prepare_complete_evpn_feed(peer, gid, None, false) {
                return (Some(feed), false);
            }
            if let Some(handle) = self.evpn_recovery_handle(peer) {
                self.evpn_recovery.fail_admission(handle);
            }
            self.mark_outbound_dirty_inner(peer, false);
            self.retry_evpn_recovery_reset(peer);
        } else if self.has_private_evpn_handoff(peer) {
            self.mark_outbound_dirty_inner(peer, false);
            return (None, true);
        }
        (None, false)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "release must sweep every typed RIB family from one atomic family gate"
    )]
    fn recompute_released_selection_family(
        &mut self,
        family: (Afi, Safi),
        stage_only: bool,
    ) -> HashSet<PeerId> {
        // Only synchronous transition/completion dispatch calls this function.
        // Its callees do not dispatch mutations; readiness checkpoints serve
        // reads, so they cannot reenter it. This scope has no await or early return.
        debug_assert!(self.selection_release_staging.is_none());
        self.wake_selection_partial_recovery(family);
        self.selection_release_staging = Some(HashSet::new());
        // A receiver that holds this family in its own Adj-RIB-Out owes it
        // whole from here: the release pass stages nothing toward it, and
        // the owed-key drain sends it one receiver per resync tick, with the
        // family's End-of-RIB held behind the debt. A unicast, labeled or
        // VPN pass does not visit the released keys for such a receiver
        // either, so its share of the release turn does not grow with the
        // table. Still per receiver times rows in this turn: a pending
        // resync of a dirty or forced receiver, the candidate scan of an
        // Add-Path, ORR or per-client-best receiver, and a deferred
        // ROUTE-REFRESH answer.
        self.owe_released_family(family);
        self.release_conditional_advertisement_family(family);
        let readiness = self.replacement_readiness.clone();
        let mut checkpoint =
            || super::replacement_readiness_checkpoint_at(&readiness, "selection_inventory", false);
        let ledger_retirement = || {
            super::replacement_readiness_checkpoint_at(
                &readiness,
                "selection_ledger_retirement",
                false,
            );
        };
        checkpoint();
        let overflowed = self
            .deferred_selection_keys
            .overflowed_families
            .contains(&family);
        let mut flowspec = ReleaseKeys::new();
        flowspec.extend(
            self.ribs
                .values()
                .inspect(|_| checkpoint())
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_flowspec)
                .inspect(|_| checkpoint())
                .filter(|route| route.family() == family)
                .map(crate::route::FlowSpecRoute::selection_key),
        );
        if overflowed && matches!(family.1, Safi::FlowSpec | Safi::FlowSpecVpn) {
            flowspec.extend(
                self.loc_rib
                    .iter_flowspec()
                    .inspect(|_| checkpoint())
                    .filter(|route| route.family() == family)
                    .map(crate::route::FlowSpecRoute::selection_key),
            );
        }
        flowspec.extend(
            self.deferred_selection_keys
                .flowspec
                .keys()
                .inspect(|_| checkpoint())
                .filter(|key| key.family() == family)
                .cloned(),
        );
        self.deferred_selection_keys.flowspec.retain(|key, ()| {
            checkpoint();
            key.family() != family
        });
        let mut flowspec = flowspec.into_set(&mut checkpoint);
        if !flowspec.is_empty() {
            self.recompute_and_distribute_flowspec(&flowspec);
            super::retire_hash_set(&mut flowspec, &mut checkpoint);
        }

        if family == (Afi::L2Vpn, Safi::Evpn) {
            let mut evpn = ReleaseKeys::new();
            evpn.extend(
                self.ribs
                    .values()
                    .inspect(|_| checkpoint())
                    .flat_map(crate::adj_rib_in::AdjRibIn::iter_evpn)
                    .inspect(|_| checkpoint())
                    .map(crate::route::EvpnRibRoute::key),
            );
            if overflowed {
                evpn.extend(
                    self.loc_rib
                        .iter_evpn()
                        .inspect(|_| checkpoint())
                        .map(crate::route::EvpnRibRoute::key),
                );
            }
            let mut retained = std::mem::take(&mut self.deferred_selection_keys.evpn);
            for shard in retained.shards_mut() {
                for (key, ()) in shard.drain() {
                    ledger_retirement();
                    evpn.insert(key);
                }
                ledger_retirement();
                drop(std::mem::take(shard));
                ledger_retirement();
            }
            ledger_retirement();
            drop(retained);
            ledger_retirement();
            let mut evpn = evpn.into_set(&mut checkpoint);
            if !evpn.is_empty() {
                self.capture_selection_evpn_before_stage();
                self.recompute_and_distribute_released_evpn(&evpn);
                // As for unicast: retire rejections whose held row is gone.
                if !self.peer_unexportable.is_empty() {
                    let gone: Vec<_> = evpn
                        .iter()
                        .inspect(|_| checkpoint())
                        .filter(|key| self.loc_rib.get_evpn(key).is_none())
                        .map(|key| crate::update::ExactExportKey::Evpn(*key))
                        .collect();
                    self.retire_exact_export_rejections(gone);
                }
                super::retire_hash_set(&mut evpn, &mut checkpoint);
            }
        }

        let mut vpn = ReleaseKeys::new();
        vpn.extend(
            self.ribs
                .values()
                .inspect(|_| checkpoint())
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_vpn_slots)
                .inspect(|_| checkpoint())
                .flatten()
                .filter(|route| route.afi_safi() == family)
                .map(crate::route::VpnRibRoute::key),
        );
        if overflowed && family.1 == Safi::MplsVpn {
            vpn.extend(
                self.loc_rib
                    .iter_vpn()
                    .inspect(|_| checkpoint())
                    .filter(|route| route.afi_safi() == family)
                    .map(crate::route::VpnRibRoute::key),
            );
        }
        vpn.extend(
            self.deferred_selection_keys
                .vpn
                .keys()
                .inspect(|_| checkpoint())
                .filter(|key| key.afi_safi() == family)
                .cloned(),
        );
        self.deferred_selection_keys.vpn.retain(|key, ()| {
            checkpoint();
            key.afi_safi() != family
        });
        let mut vpn = vpn.into_set(&mut checkpoint);
        if !vpn.is_empty() {
            self.recompute_vpn_keys(&vpn);
            if !self.peer_unexportable.is_empty() {
                let gone: Vec<_> = vpn
                    .iter()
                    .inspect(|_| checkpoint())
                    .filter(|key| self.loc_rib.get_vpn(&key.nlri_key).is_none())
                    .map(|key| crate::update::ExactExportKey::Vpn(key.clone()))
                    .collect();
                self.retire_exact_export_rejections(gone);
            }
            super::retire_hash_set(&mut vpn, &mut checkpoint);
        }

        let mut labeled = ReleaseKeys::new();
        labeled.extend(
            self.ribs
                .values()
                .inspect(|_| checkpoint())
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_labeled_slots)
                .inspect(|_| checkpoint())
                .flatten()
                .filter(|route| route.afi_safi() == family)
                .map(crate::route::LabeledRibRoute::key),
        );
        if overflowed && family.1 == Safi::LabeledUnicast {
            labeled.extend(
                self.loc_rib
                    .iter_labeled()
                    .inspect(|_| checkpoint())
                    .filter(|route| route.afi_safi() == family)
                    .map(crate::route::LabeledRibRoute::key),
            );
        }
        labeled.extend(
            self.deferred_selection_keys
                .labeled
                .keys()
                .inspect(|_| checkpoint())
                .filter(|key| key.afi_safi() == family)
                .copied(),
        );
        self.deferred_selection_keys.labeled.retain(|key, ()| {
            checkpoint();
            key.afi_safi() != family
        });
        let mut labeled = labeled.into_set(&mut checkpoint);
        if !labeled.is_empty() {
            self.recompute_labeled_keys(&labeled);
            if !self.peer_unexportable.is_empty() {
                let gone: Vec<_> = labeled
                    .iter()
                    .inspect(|_| checkpoint())
                    .filter(|key| self.loc_rib.get_labeled(&key.prefix).is_none())
                    .map(|key| crate::update::ExactExportKey::Labeled(*key))
                    .collect();
                self.retire_exact_export_rejections(gone);
            }
            super::retire_hash_set(&mut labeled, &mut checkpoint);
        }

        let mut bgpls = ReleaseKeys::new();
        bgpls.extend(
            self.ribs
                .values()
                .inspect(|_| checkpoint())
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_bgpls)
                .inspect(|_| checkpoint())
                .filter(|route| route.family.to_afi_safi() == family)
                .map(crate::route::BgpLsRibRoute::key),
        );
        if overflowed && matches!(family.1, Safi::BgpLs | Safi::BgpLsVpn) {
            bgpls.extend(
                self.loc_rib
                    .iter_bgpls()
                    .inspect(|_| checkpoint())
                    .filter(|route| route.family.to_afi_safi() == family)
                    .map(crate::route::BgpLsRibRoute::key),
            );
        }
        bgpls.extend(
            self.deferred_selection_keys
                .bgpls
                .keys()
                .inspect(|_| checkpoint())
                .filter(|key| key.family.to_afi_safi() == family)
                .cloned(),
        );
        self.deferred_selection_keys.bgpls.retain(|key, ()| {
            checkpoint();
            key.family.to_afi_safi() != family
        });
        let mut bgpls = bgpls.into_set(&mut checkpoint);
        if !bgpls.is_empty() {
            self.recompute_bgpls_keys(&bgpls);
            super::retire_hash_set(&mut bgpls, &mut checkpoint);
        }

        if family == crate::route::RtcRibRouteKey::afi_safi() {
            let mut rtc = ReleaseKeys::new();
            rtc.extend(
                self.ribs
                    .values()
                    .inspect(|_| checkpoint())
                    .flat_map(crate::adj_rib_in::AdjRibIn::iter_rtc)
                    .inspect(|_| checkpoint())
                    .map(crate::route::RtcRibRoute::key),
            );
            if overflowed {
                rtc.extend(
                    self.loc_rib
                        .iter_rtc()
                        .inspect(|_| checkpoint())
                        .map(crate::route::RtcRibRoute::key),
                );
            }
            let mut retained = std::mem::take(&mut self.deferred_selection_keys.rtc);
            for shard in retained.shards_mut() {
                for (key, ()) in shard.drain() {
                    ledger_retirement();
                    rtc.insert(key);
                }
                ledger_retirement();
                drop(std::mem::take(shard));
                ledger_retirement();
            }
            ledger_retirement();
            drop(retained);
            ledger_retirement();
            let mut rtc = rtc.into_set(&mut checkpoint);
            if !rtc.is_empty() {
                self.recompute_rtc_keys(&rtc);
                super::retire_hash_set(&mut rtc, &mut checkpoint);
            }
            let rtc_peers: Vec<_> = self
                .peer_rt_membership
                .keys()
                .inspect(|_| checkpoint())
                .copied()
                .collect();
            for peer in rtc_peers {
                checkpoint();
                self.rebuild_rtc_membership_and_restage_vpn(peer);
            }
            // RFC 4684 §6 holds whose RT-Constrain EoR arrived during the
            // deferral end here, behind the routes the rebuild emitted.
            self.publish_rebuilt_rt_memberships();
        }
        // Overflow state and logical byte budget stay sticky until every
        // typed store and RTC side effect for the family has completed.
        let readiness = &self.replacement_readiness;
        self.deferred_selection_keys
            .complete_family_release(family, &mut || {
                super::replacement_readiness_checkpoint(readiness, false);
            });
        // A collision Stage must send the table before the later release.
        // A direct release builds missing clean feeds on its paced peer visits.
        let feeds = if stage_only && family == (Afi::L2Vpn, Safi::Evpn) {
            self.prepare_selection_evpn_feeds()
        } else {
            HashMap::new()
        };
        let targets = self
            .selection_release_staging
            .take()
            .expect("family staging active");
        self.run_released_selection_resyncs(family, targets, feeds)
    }
}

#[cfg(test)]
mod ledger_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn cleared_witness_ignores_empty_shards_and_checks_accounting() {
        let mut keys = DeferredSelectionKeys {
            flowspec: ShardedMap::with_capacity(crate::fast_hash::SHARD_SPLIT_AT),
            ..DeferredSelectionKeys::default()
        };
        assert!(keys.is_cleared());
        let family = (Afi::Ipv4, Safi::Unicast);
        let prefix = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            "192.0.2.0".parse().unwrap(),
            24,
        ));
        keys.unicast.insert(prefix);
        assert!(!keys.is_cleared());
        keys.unicast.clear();
        assert!(keys.is_cleared());
        keys.overflowed_families.insert(family);
        assert!(!keys.is_cleared());
        keys.overflowed_families.clear();
        keys.retained_key_bytes_by_family.insert(family, 0);
        assert!(!keys.is_cleared());
        keys.retained_key_bytes_by_family.clear();
        keys.retained_key_bytes = 1;
        assert!(!keys.is_cleared());
        keys.retained_key_bytes = 0;
        assert!(keys.is_cleared());
    }

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
        let mut identities = ShardedMap::default();
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
            identities.keys().cloned().collect::<HashSet<_>>(),
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
            identities.keys().cloned().collect::<HashSet<_>>(),
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
        let mut identities = ShardedMap::default();
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
        assert_eq!(
            identities.keys().cloned().collect::<HashSet<_>>(),
            HashSet::from([first])
        );
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
        let mut identities = ShardedMap::default();
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
        assert!(!identities.contains_key(&huge));
    }

    #[test]
    fn byte_rejection_and_duplicate_at_cap_do_not_clone() {
        let family = (Afi::Ipv4, Safi::Unicast);
        ACCEPTED_KEY_CLONES.store(0, Ordering::SeqCst);
        REJECTED_KEY_CLONES.store(0, Ordering::SeqCst);
        let accepted = CloneCountedKey { id: 1, bytes: 1 };
        let rejected = CloneCountedKey { id: 2, bytes: 1 };
        let mut identities = ShardedMap::default();
        let mut overflowed = HashSet::new();
        let mut bytes_by_family = HashMap::new();
        let mut retained_bytes = 0;
        let limits = DeferredSelectionLimits {
            identities: usize::MAX,
            retained_key_bytes: 1,
        };

        assert_eq!(
            DeferredSelectionKeys::extend_bounded(
                &mut identities,
                &mut overflowed,
                &mut bytes_by_family,
                &mut retained_bytes,
                [(family, &accepted)],
                0,
                limits,
            )
            .len(),
            0
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
        assert_eq!(overflowed.len(), 0);
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
        ledger.complete_family_release(family_a, &mut || {});
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
        assert_eq!(overflowed.len(), 0);
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
            rd: None,
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
