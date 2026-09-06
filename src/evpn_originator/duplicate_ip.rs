//! Diagnostic IP ownership accounting; never produces origination actions.

use super::{
    BTreeMap, BTreeSet, BgpMetrics, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, Instant,
    LocalMacObservation, MacAddress, OriginatorState, RemoteMacIpViewMap, warn,
};
use rustbgpd_evpn::{DuplicateIpDetector, DuplicateIpKey, DuplicateMacDetector, DuplicateMacKey};

#[derive(Default)]
struct LocalOwners {
    macs: BTreeSet<MacAddress>,
    // A rebind arrives as IpRemoved(old), IpAdded(new). Keep the removed
    // owner only for the configured detection window, not indefinitely.
    removed: Option<(MacAddress, Instant)>,
}

type IpOwners = BTreeMap<DuplicateIpKey, BTreeMap<MacAddress, bool>>;

#[derive(Default)]
pub(super) struct DuplicateIpState {
    local: BTreeMap<DuplicateIpKey, LocalOwners>,
    remote: IpOwners,
    detector: DuplicateIpDetector,
}

impl DuplicateIpState {
    pub(super) fn expire(&mut self, now: Instant) {
        self.detector.expire(now);
        self.local.retain(|_, owners| {
            if owners.removed.is_some_and(|(_, until)| now > until) {
                owners.removed = None;
            }
            !owners.macs.is_empty() || owners.removed.is_some()
        });
    }

    pub(super) fn clear_vni(&mut self, vni: EvpnInstanceId) {
        self.local.retain(|key, _| key.vni != vni);
        self.remote.retain(|key, _| key.vni != vni);
        self.detector.clear_vni(vni);
    }

    fn remove_local(&mut self, key: DuplicateIpKey, mac: MacAddress, until: Instant) {
        if let Some(owners) = self.local.get_mut(&key)
            && owners.macs.remove(&mac)
        {
            owners.removed = Some((mac, until));
        }
    }

    fn record(
        &mut self,
        key: DuplicateIpKey,
        mac: MacAddress,
        inst: &EvpnInstance,
        metrics: &BgpMetrics,
        now: Instant,
    ) {
        metrics.record_evpn_duplicate_ip_move(key.vni.as_u32());
        let config = inst.duplicate_ip_detection;
        if self.detector.record_move(key, now, config) {
            metrics.record_evpn_duplicate_ip_threshold_exceeded(key.vni.as_u32());
            warn!(vni = ?key.vni, ip = %key.ip, mac = %mac,
                threshold = config.threshold, window_seconds = config.window.as_secs(),
                "EVPN duplicate-IP threshold exceeded; action is detect-only");
        }
    }
}

fn eligible(
    inst: &EvpnInstance,
    quarantines: &DuplicateMacDetector,
    mac: MacAddress,
    now: Instant,
) -> bool {
    !inst.sticky_macs.contains(&mac)
        && !quarantines.is_quarantined(DuplicateMacKey::new(inst.id, mac), now)
}

/// Called after cache updates, so rejected pending bindings never acquire a
/// second, unbounded cache. A Learned/recovery replay is not another IP learn.
pub(super) fn observe_local(
    obs: &LocalMacObservation,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    metrics: &BgpMetrics,
) {
    let (vni, mac) = match *obs {
        LocalMacObservation::Learned { .. } => return,
        LocalMacObservation::IpAdded { vni, mac, .. }
        | LocalMacObservation::IpRemoved { vni, mac, .. }
        | LocalMacObservation::Aged { vni, mac }
        | LocalMacObservation::ObservedOnVxlanPort { vni, mac } => (vni, mac),
    };
    let Some(inst) = instances
        .get(vni)
        .filter(|inst| inst.duplicate_ip_detection.enabled)
    else {
        return;
    };
    let now = Instant::now();
    let until = now
        .checked_add(inst.duplicate_ip_detection.window)
        .unwrap_or(now);
    let tracking = &mut state.duplicate_ip;
    match *obs {
        LocalMacObservation::IpAdded { ip, .. } => {
            let cached = state
                .live_mac_ip
                .get(&vni)
                .and_then(|macs| macs.get(&mac))
                .is_some_and(|ips| ips.contains(&ip))
                || state
                    .pending_ip_bindings
                    .get(&(vni, mac))
                    .is_some_and(|ips| ips.contains(&ip));
            if !cached {
                return;
            }
            let key = DuplicateIpKey { vni, ip };
            let owners = tracking.local.entry(key).or_default();
            if owners.macs.contains(&mac) {
                return;
            }
            let contender =
                |other| other != mac && eligible(inst, &state.duplicate_mac_detector, other, now);
            let conflict = owners.macs.iter().copied().any(contender)
                || owners
                    .removed
                    .is_some_and(|(other, until)| now <= until && contender(other))
                || tracking.remote.get(&key).is_some_and(|macs| {
                    macs.iter()
                        .any(|(&other, &sticky)| !sticky && contender(other))
                });
            owners.macs.insert(mac);
            if conflict && eligible(inst, &state.duplicate_mac_detector, mac, now) {
                tracking.record(key, mac, inst, metrics, now);
            }
        }
        LocalMacObservation::IpRemoved { ip, .. } => {
            tracking.remove_local(DuplicateIpKey { vni, ip }, mac, until);
        }
        LocalMacObservation::Aged { .. } | LocalMacObservation::ObservedOnVxlanPort { .. } => {
            for (key, owners) in &mut tracking.local {
                if key.vni == vni && owners.macs.remove(&mac) {
                    owners.removed = Some((mac, until));
                }
            }
        }
        LocalMacObservation::Learned { .. } => {}
    }
}

/// Remote membership, not sequence/next-hop changes, defines an IP learn.
/// Input already excludes our next hop and same-segment peer-sync routes.
pub(super) fn observe_remote(
    views: &RemoteMacIpViewMap,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    metrics: &BgpMetrics,
) {
    if !instances
        .iter()
        .any(|inst| inst.duplicate_ip_detection.enabled)
    {
        return;
    }
    let mut next = IpOwners::new();
    for (&(vni, mac, ip), view) in views {
        if instances
            .get(vni)
            .is_some_and(|inst| inst.duplicate_ip_detection.enabled)
        {
            next.entry(DuplicateIpKey { vni, ip })
                .or_default()
                .insert(mac, view.sticky);
        }
    }
    let now = Instant::now();
    let tracking = &mut state.duplicate_ip;
    for (&key, macs) in &next {
        let Some(inst) = instances.get(key.vni) else {
            continue;
        };
        for (&mac, &sticky) in macs {
            if sticky
                || tracking
                    .remote
                    .get(&key)
                    .is_some_and(|old| old.contains_key(&mac))
                || !eligible(inst, &state.duplicate_mac_detector, mac, now)
            {
                continue;
            }
            if tracking.local.get(&key).is_some_and(|owners| {
                owners.macs.iter().any(|&other| {
                    other != mac && eligible(inst, &state.duplicate_mac_detector, other, now)
                })
            }) {
                tracking.record(key, mac, inst, metrics, now);
            }
        }
    }
    tracking.remote = next;
}

/// A VNI redefine preserves kernel caches. Seed membership without counting
/// those cached bindings as fresh observations under the new policy.
pub(super) fn reset_vni(state: &mut OriginatorState, inst: &EvpnInstance) {
    let tracking = &mut state.duplicate_ip;
    tracking.clear_vni(inst.id);
    if !inst.duplicate_ip_detection.enabled {
        return;
    }
    if let Some(macs) = state.live_mac_ip.get(&inst.id) {
        for (&mac, ips) in macs {
            for &ip in ips {
                tracking
                    .local
                    .entry(DuplicateIpKey { vni: inst.id, ip })
                    .or_default()
                    .macs
                    .insert(mac);
            }
        }
    }
    for (&(vni, mac), ips) in &state.pending_ip_bindings {
        if vni == inst.id {
            for &ip in ips {
                tracking
                    .local
                    .entry(DuplicateIpKey { vni, ip })
                    .or_default()
                    .macs
                    .insert(mac);
            }
        }
    }
    for (&(vni, mac, ip), view) in &state.remote_mac_ip_view {
        if vni == inst.id {
            tracking
                .remote
                .entry(DuplicateIpKey { vni, ip })
                .or_default()
                .insert(mac, view.sticky);
        }
    }
}
