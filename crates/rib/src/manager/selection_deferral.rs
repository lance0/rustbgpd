//! RFC 4724 restarting-speaker route-selection deferral.
//!
//! The startup roster is frozen before the RIB actor starts.  A configured
//! peer remains a waiter until its OPEN proves that the current session is
//! GR-capable for the family and does not carry Restart State, or proves that
//! it must be excluded.  `EoR` completion is bound to that classified session.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Safi};

use super::RibManager;

#[derive(Debug, Default)]
pub(super) struct DeferredSelectionKeys {
    unicast: HashSet<rustbgpd_wire::Prefix>,
    flowspec: HashSet<crate::route::FlowSpecKey>,
    evpn: HashSet<rustbgpd_wire::EvpnRouteKey>,
    vpn: HashSet<crate::route::VpnRibRouteKey>,
    labeled: HashSet<crate::route::LabeledRibRouteKey>,
    bgpls: HashSet<crate::route::BgpLsRouteKey>,
    rtc: HashSet<crate::route::RtcRibRouteKey>,
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
    TimerExpired,
}

impl SelectionDeferralReleaseReason {
    fn label(self) -> &'static str {
        match self {
            Self::AllEndOfRib => "all_eor",
            Self::TimerExpired => "timer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaiterState {
    AwaitingSession,
    AwaitingEor { session_id: u64 },
    Satisfied { session_id: u64 },
    Excluded { session_id: u64 },
}

impl WaiterState {
    fn snapshot(self) -> (&'static str, Option<u64>) {
        match self {
            Self::AwaitingSession => ("awaiting_session", None),
            Self::AwaitingEor { session_id } => ("awaiting_eor", Some(session_id)),
            Self::Satisfied { session_id } => ("satisfied", Some(session_id)),
            Self::Excluded { session_id } => ("excluded", Some(session_id)),
        }
    }
}

#[derive(Debug)]
struct FamilyGate {
    waiters: HashMap<IpAddr, WaiterState>,
}

#[derive(Debug)]
struct ReleasedFamily {
    reason: SelectionDeferralReleaseReason,
    waiters: HashMap<IpAddr, WaiterState>,
}

/// Actor-owned selection-deferral state.  Released families are retained in
/// `released` for process-lifetime operator diagnostics; only `active` gates
/// participate in selection and outbound suppression.
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
                    WaiterState::AwaitingSession | WaiterState::AwaitingEor { .. }
                )
            })
            .count()
    }

    fn complete(gate: &FamilyGate) -> bool {
        Self::blocking_waiters(gate) == 0
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
    ) -> Vec<(Afi, Safi)> {
        if session_id == 0 || self.ambiguous_peers.contains(&peer) {
            tracing::warn!(%peer, "selection-deferral waiter received unstamped PeerUp; keeping it blocked");
            return Vec::new();
        }
        let families: Vec<_> = self.active.keys().copied().collect();
        let mut released = Vec::new();
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
            if Self::complete(gate) {
                self.release(family, SelectionDeferralReleaseReason::AllEndOfRib, metrics);
                released.push(family);
            }
        }
        released
    }

    /// Revert a current-session waiter to the not-yet-established state.  A
    /// flap cannot shrink the frozen cohort and accidentally release a family.
    pub(super) fn session_down(&mut self, peer: IpAddr, session_id: u64, metrics: &BgpMetrics) {
        for (&family, gate) in &mut self.active {
            if matches!(
                gate.waiters.get(&peer),
                Some(
                    WaiterState::AwaitingEor { session_id: current }
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

    pub(super) fn end_of_rib(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
        metrics: &BgpMetrics,
    ) -> bool {
        if session_id == 0 {
            return false;
        }
        let Some(gate) = self.active.get_mut(&family) else {
            return false;
        };
        if gate.waiters.get(&peer) != Some(&WaiterState::AwaitingEor { session_id }) {
            return false;
        }
        gate.waiters
            .insert(peer, WaiterState::Satisfied { session_id });
        metrics.set_selection_deferral_waiters(
            afi_safi_label(family.0, family.1),
            gauge_val(Self::blocking_waiters(gate)),
        );
        Self::complete(gate)
    }

    pub(super) fn finalize_all_eor(&mut self, family: (Afi, Safi), metrics: &BgpMetrics) {
        if self.active.get(&family).is_some_and(Self::complete) {
            self.release(family, SelectionDeferralReleaseReason::AllEndOfRib, metrics);
        }
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
    pub(super) fn record_deferred_unicast(&mut self, affected: &HashSet<rustbgpd_wire::Prefix>) {
        let deferred: Vec<_> = affected
            .iter()
            .filter(|prefix| self.selection_deferred(super::helpers::prefix_family(prefix)))
            .copied()
            .collect();
        self.deferred_selection_keys.unicast.extend(deferred);
    }

    pub(super) fn record_deferred_flowspec(
        &mut self,
        affected: &HashSet<crate::route::FlowSpecKey>,
    ) {
        let deferred: Vec<_> = affected
            .iter()
            .filter(|key| self.selection_deferred((key.afi, Safi::FlowSpec)))
            .cloned()
            .collect();
        self.deferred_selection_keys.flowspec.extend(deferred);
    }

    pub(super) fn record_deferred_evpn(&mut self, affected: &HashSet<rustbgpd_wire::EvpnRouteKey>) {
        if self.selection_deferred((Afi::L2Vpn, Safi::Evpn)) {
            self.deferred_selection_keys
                .evpn
                .extend(affected.iter().copied());
        }
    }

    pub(super) fn record_deferred_vpn(&mut self, affected: &HashSet<crate::route::VpnRibRouteKey>) {
        let deferred: Vec<_> = affected
            .iter()
            .filter(|key| self.selection_deferred(key.afi_safi()))
            .cloned()
            .collect();
        self.deferred_selection_keys.vpn.extend(deferred);
    }

    pub(super) fn record_deferred_labeled(
        &mut self,
        affected: &HashSet<crate::route::LabeledRibRouteKey>,
    ) {
        let deferred: Vec<_> = affected
            .iter()
            .filter(|key| self.selection_deferred(key.afi_safi()))
            .copied()
            .collect();
        self.deferred_selection_keys.labeled.extend(deferred);
    }

    pub(super) fn record_deferred_bgpls(
        &mut self,
        affected: &HashSet<crate::route::BgpLsRouteKey>,
    ) {
        let deferred: Vec<_> = affected
            .iter()
            .filter(|key| self.selection_deferred(key.family.to_afi_safi()))
            .cloned()
            .collect();
        self.deferred_selection_keys.bgpls.extend(deferred);
    }

    pub(super) fn record_deferred_rtc(&mut self, affected: &HashSet<crate::route::RtcRibRouteKey>) {
        if self.selection_deferred(crate::route::RtcRibRouteKey::afi_safi()) {
            self.deferred_selection_keys
                .rtc
                .extend(affected.iter().cloned());
        }
    }

    /// Consume a current-session `EoR` in the startup gate. The caller invokes
    /// the ordinary GR/LLGR `EoR` handler after this, then recomputes the released
    /// family against the complete Adj-RIB-In cohort.
    pub(super) fn selection_deferral_end_of_rib(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        family: (Afi, Safi),
    ) -> bool {
        self.selection_deferral
            .as_mut()
            .is_some_and(|selection| selection.end_of_rib(peer, session_id, family, &self.metrics))
    }

    pub(super) fn finalize_selection_deferral_all_eor(&mut self, family: (Afi, Safi)) {
        if let Some(selection) = self.selection_deferral.as_mut() {
            selection.finalize_all_eor(family, &self.metrics);
        }
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

    /// Run the delayed family selection exactly once after its gate opens.
    /// All identity sets come from Adj-RIB-In, which continued accepting the
    /// current sessions' updates while Loc-RIB selection was frozen.
    pub(super) fn release_selection_families(
        &mut self,
        families: &[(Afi, Safi)],
        reason: &'static str,
    ) {
        for &family in families {
            tracing::info!(
                afi = ?family.0,
                safi = ?family.1,
                reason,
                "RFC 4724 route-selection deferral released"
            );
            self.recompute_released_selection_family(family);
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
                self.send_route_refresh_response(peer, family.0, family.1);
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "release must sweep every typed RIB family from one atomic family gate"
    )]
    fn recompute_released_selection_family(&mut self, family: (Afi, Safi)) {
        let mut prefixes: HashSet<_> = self
            .ribs
            .values()
            .flat_map(crate::adj_rib_in::AdjRibIn::iter)
            .filter(|route| super::helpers::prefix_family(&route.prefix) == family)
            .map(|route| route.prefix)
            .collect();
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
            rtc.extend(self.deferred_selection_keys.rtc.drain());
            if !rtc.is_empty() {
                self.recompute_rtc_keys(&rtc);
            }
            let rtc_peers: Vec<_> = self.peer_rt_membership.keys().copied().collect();
            for peer in rtc_peers {
                self.rebuild_rtc_membership_and_restage_vpn(peer);
            }
        }
    }
}
