use std::collections::{HashMap, HashSet};
use std::pin::Pin;

use rustbgpd_rib::{
    BgpLsFamily, BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecKey, FlowSpecRoute,
    LabeledRibRoute, LabeledRibRouteKey, Route, RtcRibRoute, RtcRibRouteKey, VpnRibRoute,
    VpnRibRouteKey,
};
use rustbgpd_wire::{Afi, EvpnRouteKey, Prefix, Safi};
use tokio::time::{Instant, Sleep};

use super::PeerSession;

type Family = (Afi, Safi);

/// Transport-owned RFC 7313 windows. These exist only while an inbound
/// enhanced refresh is active; the ordinary no-refresh UPDATE path pays one
/// `is_empty` branch and retains no per-route generation state.
#[derive(Default)]
pub(super) struct RefreshMaxPrefixAccounting {
    windows: HashMap<Family, RefreshMaxPrefixWindow>,
}

struct RefreshMaxPrefixWindow {
    deadline: Instant,
    stale: RefreshStaleIdentities,
}

enum RefreshStaleIdentities {
    Unicast(HashSet<(Prefix, u32)>),
    FlowSpec(HashSet<FlowSpecKey>),
    Evpn(HashSet<EvpnRouteKey>),
    BgpLs(HashSet<BgpLsRouteKey>),
    Vpn(HashSet<VpnRibRouteKey>),
    Labeled(HashSet<LabeledRibRouteKey>),
    Rtc(HashSet<RtcRibRouteKey>),
    Uncounted,
}

/// Identities whose corresponding RIB update was accepted by the actor
/// channel. Applying the delta after the send is what prevents an import-policy
/// denial or failed RIB enqueue from falsely marking a stale route as replayed.
#[derive(Default)]
pub(super) struct RefreshAccountingDelta {
    unicast: Vec<(Prefix, u32)>,
    flowspec: Vec<FlowSpecKey>,
    evpn: Vec<EvpnRouteKey>,
    bgpls: Vec<BgpLsRouteKey>,
    vpn: Vec<VpnRibRouteKey>,
    labeled: Vec<LabeledRibRouteKey>,
    rtc: Vec<RtcRibRouteKey>,
}

impl PeerSession {
    /// Open or replace the exact family window after `BeginRouteRefresh` has
    /// been accepted by the RIB channel. A duplicate `BoRR` deliberately takes a
    /// fresh snapshot and deadline.
    pub(super) fn begin_refresh_accounting(&mut self, afi: Afi, safi: Safi) {
        let family = (afi, safi);
        let stale = match family {
            (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast) => RefreshStaleIdentities::Unicast(
                self.known_paths
                    .iter()
                    .copied()
                    .filter(|(prefix, _)| unicast_family(*prefix) == family)
                    .collect(),
            ),
            (_, Safi::FlowSpec) => RefreshStaleIdentities::FlowSpec(
                self.known_flowspec
                    .iter()
                    .filter(|key| key.afi == afi)
                    .cloned()
                    .collect(),
            ),
            (Afi::L2Vpn, Safi::Evpn) => RefreshStaleIdentities::Evpn(self.known_evpn.clone()),
            _ if BgpLsFamily::from_afi_safi(afi, safi).is_some() => RefreshStaleIdentities::BgpLs(
                self.known_bgpls
                    .iter()
                    .filter(|key| key.family.to_afi_safi() == family)
                    .cloned()
                    .collect(),
            ),
            (_, Safi::MplsVpn) => RefreshStaleIdentities::Vpn(
                self.known_vpn
                    .iter()
                    .filter(|key| key.afi_safi() == family)
                    .cloned()
                    .collect(),
            ),
            (_, Safi::LabeledUnicast) => RefreshStaleIdentities::Labeled(
                self.known_labeled
                    .iter()
                    .filter(|key| key.afi_safi() == family)
                    .copied()
                    .collect(),
            ),
            (Afi::Ipv4, Safi::RtConstrain) => RefreshStaleIdentities::Rtc(self.known_rtc.clone()),
            _ => RefreshStaleIdentities::Uncounted,
        };
        self.refresh_accounting.windows.insert(
            family,
            RefreshMaxPrefixWindow {
                deadline: Instant::now() + rustbgpd_rib::ERR_REFRESH_TIMEOUT,
                stale,
            },
        );
        self.arm_refresh_accounting_timer();
    }

    /// Consume an explicit `EoRR` window before sweeping its remaining stale
    /// identities from the live max-prefix authority. A stray `EoRR` is a no-op.
    pub(super) fn end_refresh_accounting(&mut self, afi: Afi, safi: Safi) {
        let Some(window) = self.refresh_accounting.windows.remove(&(afi, safi)) else {
            return;
        };
        self.arm_refresh_accounting_timer();
        self.sweep_refresh_accounting(window.stale);
    }

    /// Reconcile every due family. Called before each buffered PDU decode and
    /// from the independent quiet-session run-loop timer.
    ///
    /// The timeout is first enqueued to the RIB as an ordinary `EoRR` so it is
    /// ordered ahead of the next UPDATE from this session. Only after that send
    /// succeeds may transport consume/sweep the matching local window. The
    /// RIB's own timer remains an idempotent safety net.
    pub(super) async fn expire_refresh_accounting_windows(&mut self) -> Result<(), ()> {
        if self.refresh_accounting.windows.is_empty() {
            self.refresh_accounting_timer = None;
            return Ok(());
        }

        loop {
            // Recompute after every awaited send: another family can become due
            // while the RIB channel is applying backpressure.
            let now = Instant::now();
            let next_due = self
                .refresh_accounting
                .windows
                .iter()
                .filter(|&(_, window)| window.deadline <= now)
                .min_by_key(|&(&(afi, safi), window)| (window.deadline, afi as u16, safi as u8))
                .map(|(&family, _)| family);
            let Some((afi, safi)) = next_due else {
                self.arm_refresh_accounting_timer();
                return Ok(());
            };

            if self
                .rib_tx
                .send(rustbgpd_rib::RibUpdate::EndRouteRefresh {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    afi,
                    safi,
                })
                .await
                .is_err()
            {
                // Preserve this and every later window. Re-arming an already
                // elapsed deadline would spin the run loop while the RIB is
                // gone; a later inbound decode may retry, and shutdown can win.
                self.refresh_accounting_timer = None;
                tracing::warn!(
                    peer = %self.peer_label,
                    ?afi,
                    ?safi,
                    "RIB manager unavailable — timed-out refresh accounting remains unswept"
                );
                return Err(());
            }

            tracing::warn!(
                peer = %self.peer_label,
                ?afi,
                ?safi,
                timeout_secs = rustbgpd_rib::ERR_REFRESH_TIMEOUT.as_secs(),
                "enhanced route refresh timed out — reconciling max-prefix accounting"
            );
            self.end_refresh_accounting(afi, safi);
        }
    }

    pub(super) fn clear_refresh_accounting(&mut self) {
        self.refresh_accounting.windows.clear();
        self.refresh_accounting_timer = None;
    }

    fn arm_refresh_accounting_timer(&mut self) {
        self.refresh_accounting_timer = self
            .refresh_accounting
            .windows
            .values()
            .map(|window| window.deadline)
            .min()
            .map(|deadline| Box::pin(tokio::time::sleep_until(deadline)) as Pin<Box<Sleep>>);
    }

    fn sweep_refresh_accounting(&mut self, stale: RefreshStaleIdentities) {
        match stale {
            RefreshStaleIdentities::Unicast(keys) => {
                for (prefix, path_id) in keys {
                    self.forget_known_path(prefix, path_id);
                }
            }
            RefreshStaleIdentities::FlowSpec(keys) => {
                for key in keys {
                    self.known_flowspec.remove(&key);
                }
            }
            RefreshStaleIdentities::Evpn(keys) => {
                for key in keys {
                    self.known_evpn.remove(&key);
                }
            }
            RefreshStaleIdentities::BgpLs(keys) => {
                for key in keys {
                    self.known_bgpls.remove(&key);
                }
            }
            RefreshStaleIdentities::Vpn(keys) => {
                for key in keys {
                    self.known_vpn.remove(&key);
                }
            }
            RefreshStaleIdentities::Labeled(keys) => {
                for key in keys {
                    self.known_labeled.remove(&key);
                }
            }
            RefreshStaleIdentities::Rtc(keys) => {
                for key in keys {
                    self.known_rtc.remove(&key);
                }
            }
            RefreshStaleIdentities::Uncounted => {}
        }
    }

    pub(super) fn capture_routes_refresh_delta(
        &self,
        announced: &[Route],
        withdrawn: &[(Prefix, u32)],
        flowspec_announced: &[FlowSpecRoute],
        flowspec_withdrawn: &[FlowSpecKey],
        evpn_announced: &[EvpnRibRoute],
        evpn_withdrawn: &[EvpnRouteKey],
    ) -> Option<RefreshAccountingDelta> {
        if self.refresh_accounting.windows.is_empty() {
            return None;
        }
        let mut delta = RefreshAccountingDelta::default();
        delta.unicast.extend(
            announced
                .iter()
                .map(|route| (route.prefix, route.path_id))
                .chain(withdrawn.iter().copied())
                .filter(|(prefix, _)| {
                    self.refresh_accounting
                        .windows
                        .contains_key(&unicast_family(*prefix))
                }),
        );
        delta.flowspec.extend(
            flowspec_announced
                .iter()
                .map(FlowSpecRoute::selection_key)
                .chain(flowspec_withdrawn.iter().cloned())
                .filter(|key| {
                    self.refresh_accounting
                        .windows
                        .contains_key(&(key.afi, Safi::FlowSpec))
                }),
        );
        if self
            .refresh_accounting
            .windows
            .contains_key(&(Afi::L2Vpn, Safi::Evpn))
        {
            delta
                .evpn
                .extend(evpn_announced.iter().map(EvpnRibRoute::key));
            delta.evpn.extend(evpn_withdrawn.iter().copied());
        }
        Some(delta)
    }

    pub(super) fn capture_bgpls_refresh_delta(
        &self,
        announced: &[BgpLsRibRoute],
        withdrawn: &[BgpLsRouteKey],
    ) -> Option<RefreshAccountingDelta> {
        if self.refresh_accounting.windows.is_empty() {
            return None;
        }
        let mut delta = RefreshAccountingDelta::default();
        delta.bgpls.extend(
            announced
                .iter()
                .map(BgpLsRibRoute::key)
                .chain(withdrawn.iter().cloned())
                .filter(|key| {
                    self.refresh_accounting
                        .windows
                        .contains_key(&key.family.to_afi_safi())
                }),
        );
        Some(delta)
    }

    pub(super) fn capture_vpn_refresh_delta(
        &self,
        announced: &[VpnRibRoute],
        withdrawn: &[VpnRibRouteKey],
    ) -> Option<RefreshAccountingDelta> {
        if self.refresh_accounting.windows.is_empty() {
            return None;
        }
        let mut delta = RefreshAccountingDelta::default();
        delta.vpn.extend(
            announced
                .iter()
                .map(VpnRibRoute::key)
                .chain(withdrawn.iter().cloned())
                .filter(|key| {
                    self.refresh_accounting
                        .windows
                        .contains_key(&key.afi_safi())
                }),
        );
        Some(delta)
    }

    pub(super) fn capture_labeled_refresh_delta(
        &self,
        announced: &[LabeledRibRoute],
        withdrawn: &[LabeledRibRouteKey],
    ) -> Option<RefreshAccountingDelta> {
        if self.refresh_accounting.windows.is_empty() {
            return None;
        }
        let mut delta = RefreshAccountingDelta::default();
        delta.labeled.extend(
            announced
                .iter()
                .map(LabeledRibRoute::key)
                .chain(withdrawn.iter().copied())
                .filter(|key| {
                    self.refresh_accounting
                        .windows
                        .contains_key(&key.afi_safi())
                }),
        );
        Some(delta)
    }

    pub(super) fn capture_rtc_refresh_delta(
        &self,
        announced: &[RtcRibRoute],
        withdrawn: &[RtcRibRouteKey],
    ) -> Option<RefreshAccountingDelta> {
        if self.refresh_accounting.windows.is_empty() {
            return None;
        }
        let family = RtcRibRouteKey::afi_safi();
        let mut delta = RefreshAccountingDelta::default();
        if self.refresh_accounting.windows.contains_key(&family) {
            delta.rtc.extend(announced.iter().map(RtcRibRoute::key));
            delta.rtc.extend(withdrawn.iter().cloned());
        }
        Some(delta)
    }

    pub(super) fn apply_refresh_accounting_delta(&mut self, delta: RefreshAccountingDelta) {
        for (prefix, path_id) in delta.unicast {
            if let Some(RefreshMaxPrefixWindow {
                stale: RefreshStaleIdentities::Unicast(stale),
                ..
            }) = self
                .refresh_accounting
                .windows
                .get_mut(&unicast_family(prefix))
            {
                stale.remove(&(prefix, path_id));
            }
        }
        for key in delta.flowspec {
            if let Some(RefreshMaxPrefixWindow {
                stale: RefreshStaleIdentities::FlowSpec(stale),
                ..
            }) = self
                .refresh_accounting
                .windows
                .get_mut(&(key.afi, Safi::FlowSpec))
            {
                stale.remove(&key);
            }
        }
        if let Some(RefreshMaxPrefixWindow {
            stale: RefreshStaleIdentities::Evpn(stale),
            ..
        }) = self
            .refresh_accounting
            .windows
            .get_mut(&(Afi::L2Vpn, Safi::Evpn))
        {
            for key in delta.evpn {
                stale.remove(&key);
            }
        }
        for key in delta.bgpls {
            if let Some(RefreshMaxPrefixWindow {
                stale: RefreshStaleIdentities::BgpLs(stale),
                ..
            }) = self
                .refresh_accounting
                .windows
                .get_mut(&key.family.to_afi_safi())
            {
                stale.remove(&key);
            }
        }
        for key in delta.vpn {
            if let Some(RefreshMaxPrefixWindow {
                stale: RefreshStaleIdentities::Vpn(stale),
                ..
            }) = self.refresh_accounting.windows.get_mut(&key.afi_safi())
            {
                stale.remove(&key);
            }
        }
        for key in delta.labeled {
            if let Some(RefreshMaxPrefixWindow {
                stale: RefreshStaleIdentities::Labeled(stale),
                ..
            }) = self.refresh_accounting.windows.get_mut(&key.afi_safi())
            {
                stale.remove(&key);
            }
        }
        let rtc_family = RtcRibRouteKey::afi_safi();
        if let Some(RefreshMaxPrefixWindow {
            stale: RefreshStaleIdentities::Rtc(stale),
            ..
        }) = self.refresh_accounting.windows.get_mut(&rtc_family)
        {
            for key in delta.rtc {
                stale.remove(&key);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn refresh_accounting_window_count(&self) -> usize {
        self.refresh_accounting.windows.len()
    }

    #[cfg(test)]
    pub(super) fn refresh_accounting_has_window(&self, family: Family) -> bool {
        self.refresh_accounting.windows.contains_key(&family)
    }

    #[cfg(test)]
    pub(super) fn refresh_accounting_stale_count(&self, family: Family) -> Option<usize> {
        self.refresh_accounting
            .windows
            .get(&family)
            .map(|window| match &window.stale {
                RefreshStaleIdentities::Unicast(keys) => keys.len(),
                RefreshStaleIdentities::FlowSpec(keys) => keys.len(),
                RefreshStaleIdentities::Evpn(keys) => keys.len(),
                RefreshStaleIdentities::BgpLs(keys) => keys.len(),
                RefreshStaleIdentities::Vpn(keys) => keys.len(),
                RefreshStaleIdentities::Labeled(keys) => keys.len(),
                RefreshStaleIdentities::Rtc(keys) => keys.len(),
                RefreshStaleIdentities::Uncounted => 0,
            })
    }
}

const fn unicast_family(prefix: Prefix) -> Family {
    match prefix {
        Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
        Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
    }
}
