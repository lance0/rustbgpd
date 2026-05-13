//! Daemon-side SVI-MAC origination (RFC 9135 §6.1).
//!
//! When an `[[evpn_instances]]` entry sets `advertise_svi_mac = true`,
//! the daemon must originate a Type 2 (MAC/IP Advertisement, RFC 7432
//! §7.2) for the **bridge's own** MAC address — the SVI MAC. This
//! lets remote VTEPs target the bridge for inter-subnet traffic
//! without needing an upstream gateway MAC discovery dance.
//!
//! Boundary: the bridge MAC is observed by the Linux dataplane
//! (`crates/evpn-linux`) and surfaced through the existing
//! `DataplaneReport` broadcast — specifically on
//! `InstanceDataplaneStatus.bridge_mac`. The SVI task subscribes to
//! that broadcast, never reaches into the dataplane crate's
//! `LinkCache`, and never spawns netlink work of its own.
//! ADR-0054 §1 stays clean: Linux observes, daemon decides.
//!
//! ## State machine
//!
//! Per-VNI state is `Option<(EvpnRouteKey, MacAddress)>` — what's
//! currently advertised, if anything. Each `DataplaneReport` row
//! produces a desired view:
//!
//! ```text
//! want = match (state, bridge_mac) {
//!     (Ready, Some(mac)) => Some(mac),       // canonical happy path
//!     _                  => None,            // NotReady / Unbound / no MAC
//! }
//! ```
//!
//! And the transition matrix is:
//!
//! | originated      | want      | action                          |
//! |-----------------|-----------|---------------------------------|
//! | None            | None      | no-op                           |
//! | None            | Some(mac) | originate                       |
//! | Some(_, cur)    | None      | withdraw                        |
//! | Some(_, cur)    | Some(new) `cur == new` → no-op            |
//! | Some(_, cur)    | Some(new) `cur != new` → withdraw + originate |
//!
//! The bridge-MAC-change branch (Cumulus and friends will
//! occasionally re-pick a lower-MAC port if not pinned) emits a
//! Withdraw for the old key before re-originating, so contenders
//! never see two best paths for the SVI MAC at once.
//!
//! ## Counter accounting
//!
//! The daemon's `OriginatedLocalMacCounts` is shared across the
//! local-MAC originator and this task. SVI MACs participate in the
//! same VNI counter via `record_inject` / `record_withdraw` so
//! `rustbgpctl evpn instances` reports the full picture.
//!
//! ## RR-only / inert path
//!
//! When no instance has `advertise_svi_mac = true`, [`spawn`] returns
//! `None` and no background task is created. RR-only deployments
//! (which never reach the SVI path) take the `evpn_instances.is_empty()`
//! short-circuit one layer up via `EvpnDataplaneHandle` not being
//! constructed at all — this module is a no-op for them.
//!
//! ## Reference
//!
//! - ADR-0054 §1, §6 (boundary + level-triggered model)
//! - ADR-0055 §7 (deferred MAC-with-IP origination — the SVI path
//!   here ships the no-IP shape)
//! - RFC 7432 §7.2 (Type 2 NLRI shape)
//! - RFC 9135 §6.1 (default-gateway / SVI MAC advertisement)

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::{
    DataplaneReport, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, InstanceState, MacAddress,
};
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{EthernetTagId, EvpnRouteKey, RouteDistinguisher};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::evpn_originator::{OriginatedLocalMacCounts, build_originated_route};

/// Handle returned to the daemon for shutdown coordination. Holding
/// this alive keeps the SVI task running.
#[derive(Debug)]
pub struct EvpnSviHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

impl EvpnSviHandle {
    /// Cancel the actor and wait for it to drain. Drain emits
    /// Withdraws for any still-advertised SVI MACs so peer state
    /// converges before the daemon exits.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.join).await;
    }
}

/// Spawn the SVI-MAC origination task. Returns `None` when no
/// instance has `advertise_svi_mac = true` — the typical case, where
/// no background task is created.
#[must_use = "drop the handle to shut down the SVI-MAC origination task"]
pub fn spawn(
    evpn_instances: &Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    report_rx: broadcast::Receiver<DataplaneReport>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    daemon_shutdown: CancellationToken,
) -> Option<EvpnSviHandle> {
    if !evpn_instances.iter().any(|i| i.advertise_svi_mac) {
        info!("no [[evpn_instances]] has advertise_svi_mac=true; SVI-MAC task not spawned");
        return None;
    }
    let runtime = SviRuntime {
        instances: evpn_instances.clone(),
        rib_tx,
        metrics,
        originated_local_mac_counts,
        shutdown: daemon_shutdown.clone(),
    };
    let join = tokio::spawn(svi_loop(runtime, report_rx));
    Some(EvpnSviHandle {
        shutdown: daemon_shutdown,
        join,
    })
}

struct SviRuntime {
    instances: Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    shutdown: CancellationToken,
}

/// Per-VNI tracker of what's currently advertised for the SVI MAC.
type OriginatedSet = BTreeMap<EvpnInstanceId, (EvpnRouteKey, MacAddress)>;

async fn svi_loop(runtime: SviRuntime, mut report_rx: broadcast::Receiver<DataplaneReport>) {
    let mut originated: OriginatedSet = BTreeMap::new();

    loop {
        tokio::select! {
            biased;
            () = runtime.shutdown.cancelled() => {
                drain_to_withdraws(&mut originated, &runtime).await;
                return;
            }
            recv = report_rx.recv() => match recv {
                Ok(report) => apply_report(&report, &mut originated, &runtime).await,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // Reports are level-triggered (full instance_status
                    // re-emitted every reconcile pass), so the next
                    // recv carries fresh state for every instance.
                    // Just log and keep going.
                    warn!(skipped, "EVPN SVI: dataplane report broadcast lagged");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    debug!("EVPN SVI: dataplane report broadcast closed; shutting down");
                    drain_to_withdraws(&mut originated, &runtime).await;
                    return;
                }
            },
        }
    }
}

/// Apply one [`DataplaneReport`] — walks every status row and runs
/// the per-VNI transition matrix described in the module-level docs.
async fn apply_report(
    report: &DataplaneReport,
    originated: &mut OriginatedSet,
    runtime: &SviRuntime,
) {
    for status in &report.instance_status {
        let Some(inst) = runtime.instances.get(status.vni) else {
            continue;
        };
        if !inst.advertise_svi_mac {
            continue;
        }

        let want: Option<MacAddress> = match (status.state, status.bridge_mac) {
            (InstanceState::Ready, Some(mac)) => Some(mac),
            _ => None,
        };
        let current = originated.get(&status.vni).copied();

        match (current, want) {
            (None, None) => {}
            (None, Some(mac)) => {
                if let Some(key) = inject_svi_mac(inst, mac, runtime).await {
                    originated.insert(status.vni, (key, mac));
                }
            }
            (Some((key, _)), None) => {
                withdraw_svi_mac(inst, key, runtime).await;
                originated.remove(&status.vni);
            }
            (Some((_, cur)), Some(new)) if cur == new => {}
            (Some((old_key, old_mac)), Some(new_mac)) => {
                withdraw_svi_mac(inst, old_key, runtime).await;
                runtime
                    .originated_local_mac_counts
                    .record_withdraw(inst.id, old_mac, old_key);
                if let Some(new_key) = inject_svi_mac(inst, new_mac, runtime).await {
                    originated.insert(status.vni, (new_key, new_mac));
                } else {
                    originated.remove(&status.vni);
                }
            }
        }
    }
}

/// Build the Type 2 route for the SVI MAC and Inject it into the
/// RIB. Returns the route key on success so the caller can stash it
/// for a later Withdraw. Failures are logged through the existing
/// metrics surface and yield `None`.
async fn inject_svi_mac(
    inst: &EvpnInstance,
    mac: MacAddress,
    runtime: &SviRuntime,
) -> Option<EvpnRouteKey> {
    let key = svi_mac_key(inst.rd, mac);
    // SVI MAC origination uses no mobility seq (no contender to
    // defend against — this is a steady-state advertisement of the
    // bridge's own MAC). The sticky bit (RFC 7432 §15.4) is set
    // when the operator listed the bridge MAC in `sticky_macs` —
    // ADR-0056 is explicit that this is the supported way to mark
    // an SVI MAC sticky on origination.
    let sticky = inst.sticky_macs.contains(&mac);
    // SVI MAC is the L3 next-hop for the local PE's bridge, not a
    // CE-side MAC. It always advertises with ESI=0 (single-homed
    // sentinel) regardless of whether the VNI participates in a
    // configured Ethernet Segment — peers don't aliasing-resolve
    // SVI MACs. Matches FRR / Cumulus behavior.
    let route = build_originated_route(
        inst,
        mac,
        None,
        sticky,
        key,
        rustbgpd_wire::EthernetSegmentIdentifier::ZERO,
    );
    let (reply_tx, reply_rx) = oneshot::channel();
    if runtime
        .rib_tx
        .send(RibUpdate::InjectEvpn {
            route,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        runtime
            .metrics
            .record_evpn_local_origination_error("svi_inject");
        warn!(?key, "EVPN SVI: RIB channel closed; cannot inject SVI MAC");
        return None;
    }
    match reply_rx.await {
        Ok(Ok(())) => {
            runtime.metrics.record_evpn_local_origination("svi_inject");
            runtime
                .originated_local_mac_counts
                .record_inject(inst.id, mac, key);
            debug!(vni = inst.id.as_u32(), ?mac, "originated SVI MAC");
            Some(key)
        }
        Ok(Err(e)) => {
            runtime
                .metrics
                .record_evpn_local_origination_error("svi_inject");
            warn!(?key, error = %e, "EVPN SVI: RIB rejected SVI MAC inject");
            None
        }
        Err(_) => {
            runtime
                .metrics
                .record_evpn_local_origination_error("svi_inject");
            warn!(?key, "EVPN SVI: RIB inject reply dropped");
            None
        }
    }
}

/// Withdraw a previously-injected SVI MAC route. Counter accounting
/// for the success case lives at the call site (the bridge-MAC-change
/// path needs to decrement before the new injection can record).
async fn withdraw_svi_mac(inst: &EvpnInstance, key: EvpnRouteKey, runtime: &SviRuntime) {
    let (reply_tx, reply_rx) = oneshot::channel();
    if runtime
        .rib_tx
        .send(RibUpdate::WithdrawEvpn {
            key,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        runtime
            .metrics
            .record_evpn_local_origination_error("svi_withdraw");
        warn!(
            ?key,
            "EVPN SVI: RIB channel closed; cannot withdraw SVI MAC"
        );
        return;
    }
    match reply_rx.await {
        Ok(Ok(())) => {
            runtime
                .metrics
                .record_evpn_local_origination("svi_withdraw");
            // Counter decrement only happens for the steady-state
            // (Some, None) transition — the (Some, Some) bridge-MAC
            // change path manages it explicitly to keep the counter
            // monotonic across the withdraw + reinject pair.
            if let Some(mac) = mac_from_macip_key(&key) {
                runtime
                    .originated_local_mac_counts
                    .record_withdraw(inst.id, mac, key);
            }
            debug!(vni = inst.id.as_u32(), "withdrew SVI MAC");
        }
        Ok(Err(e)) => {
            // Withdraw of an unknown key can race with a prior
            // failed inject; log at debug and let the next reconcile
            // pass converge.
            debug!(?key, error = %e, "EVPN SVI: RIB withdraw declined");
        }
        Err(_) => {
            runtime
                .metrics
                .record_evpn_local_origination_error("svi_withdraw");
            warn!(?key, "EVPN SVI: RIB withdraw reply dropped");
        }
    }
}

/// Build the synthetic Type 2 key for an SVI MAC. The shape mirrors
/// what `LocalMacOriginator` produces for kernel-learned MACs:
/// `ethernet_tag = 0`, no host IP. Keeping the shapes aligned means
/// downstream consumers (peers, BMP) treat SVI MACs the same as any
/// other Type 2 entry.
fn svi_mac_key(rd: RouteDistinguisher, mac: MacAddress) -> EvpnRouteKey {
    EvpnRouteKey::MacIp {
        rd,
        ethernet_tag: EthernetTagId(0),
        mac,
        ip: None,
    }
}

/// Pull the MAC out of a [`EvpnRouteKey::MacIp`] for counter accounting.
fn mac_from_macip_key(key: &EvpnRouteKey) -> Option<MacAddress> {
    match key {
        EvpnRouteKey::MacIp { mac, .. } => Some(*mac),
        _ => None,
    }
}

/// On shutdown, withdraw every still-advertised SVI MAC so peer state
/// converges before the daemon exits.
async fn drain_to_withdraws(originated: &mut OriginatedSet, runtime: &SviRuntime) {
    for (vni, (key, mac)) in std::mem::take(originated) {
        let Some(inst) = runtime.instances.get(vni) else {
            continue;
        };
        // Direct send + ack — apply_actions logging surface is reused
        // through withdraw_svi_mac.
        withdraw_svi_mac(inst, key, runtime).await;
        runtime
            .originated_local_mac_counts
            .record_withdraw(vni, mac, key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_evpn::{
        DataplaneReport, EvpnInstance, EvpnInstanceTable, InstanceDataplaneStatus, RouteTarget,
    };
    use rustbgpd_rib::route::EvpnRibRoute;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn rd_for(asn: u16, val: u32) -> RouteDistinguisher {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&val.to_be_bytes());
        RouteDistinguisher::new(bytes)
    }

    fn instance(vni_val: u32, advertise_svi: bool) -> EvpnInstance {
        EvpnInstance::new(
            vni(vni_val),
            rd_for(65000, vni_val),
            vec![RouteTarget::TwoOctetAs {
                asn: 65000,
                value: vni_val,
            }],
            "10.0.0.1".parse().unwrap(),
            Some(format!("br{vni_val}")),
            advertise_svi,
        )
        .unwrap()
    }

    fn instance_table(advertise_svi: bool) -> Arc<EvpnInstanceTable> {
        let mut t = EvpnInstanceTable::new();
        t.insert(instance(100, advertise_svi)).unwrap();
        Arc::new(t)
    }

    fn report_with(vni_val: u32, state: InstanceState, mac: Option<MacAddress>) -> DataplaneReport {
        DataplaneReport {
            intent_generation: 0,
            reconcile_generation: 0,
            instance_status: vec![InstanceDataplaneStatus {
                vni: vni(vni_val),
                state,
                message: None,
                bridge_mac: mac,
            }],
            applied: vec![],
            failed: vec![],
            bum_enforcement: vec![],
            ip_vrf_status: vec![],
            ip_vrf_routes: Some(rustbgpd_evpn::ip_vrf::IpVrfRouteDump::default()),
            ip_vrf_installed_routes: std::collections::HashMap::new(),
            fdb_nexthops: rustbgpd_evpn::FdbNexthopDataplaneStatus::default(),
            fdb_nhg_drift_counters: rustbgpd_evpn::FdbNhgDriftCounters::default(),
        }
    }

    fn drain_responder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        captured: Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
        withdraws: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { route, reply } => {
                        captured.lock().await.push(route);
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        withdraws.lock().await.push(key);
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    /// `(None, Ready+mac)` — first observation must originate exactly
    /// one Inject. The plan called this out as a regression target
    /// against the older "transition-based" pseudocode.
    #[tokio::test]
    async fn first_ready_with_mac_originates() {
        let instances = instance_table(true);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = drain_responder(rib_rx, captured.clone(), withdraws.clone());

        let runtime = SviRuntime {
            instances,
            rib_tx,
            metrics: BgpMetrics::new(),
            originated_local_mac_counts: OriginatedLocalMacCounts::default(),
            shutdown: CancellationToken::new(),
        };
        let mut originated = OriginatedSet::new();

        let svi_mac = MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        apply_report(
            &report_with(100, InstanceState::Ready, Some(svi_mac)),
            &mut originated,
            &runtime,
        )
        .await;

        assert_eq!(originated.len(), 1, "expected one origination");
        let (_, mac) = originated.get(&vni(100)).unwrap();
        assert_eq!(*mac, svi_mac);
        assert_eq!(captured.lock().await.len(), 1, "exactly one Inject");
        assert!(withdraws.lock().await.is_empty());
    }

    /// Bridge-MAC change must withdraw the old key and inject the new
    /// one — two RIB ops, in that order.
    #[tokio::test]
    async fn bridge_mac_change_withdraws_then_reoriginates() {
        let instances = instance_table(true);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = drain_responder(rib_rx, captured.clone(), withdraws.clone());

        let runtime = SviRuntime {
            instances,
            rib_tx,
            metrics: BgpMetrics::new(),
            originated_local_mac_counts: OriginatedLocalMacCounts::default(),
            shutdown: CancellationToken::new(),
        };
        let mut originated = OriginatedSet::new();

        let mac_a = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x0A]);
        let mac_b = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x0B]);
        apply_report(
            &report_with(100, InstanceState::Ready, Some(mac_a)),
            &mut originated,
            &runtime,
        )
        .await;
        apply_report(
            &report_with(100, InstanceState::Ready, Some(mac_b)),
            &mut originated,
            &runtime,
        )
        .await;

        let injects = captured.lock().await;
        let withdraws = withdraws.lock().await;
        assert_eq!(injects.len(), 2, "two Injects: original + post-change");
        assert_eq!(withdraws.len(), 1, "one Withdraw for the old key");
    }

    /// `Ready -> NotReady` (e.g. operator deletes the bridge) must
    /// withdraw the previously-originated SVI MAC.
    #[tokio::test]
    async fn ready_to_notready_withdraws() {
        let instances = instance_table(true);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = drain_responder(rib_rx, captured.clone(), withdraws.clone());

        let runtime = SviRuntime {
            instances,
            rib_tx,
            metrics: BgpMetrics::new(),
            originated_local_mac_counts: OriginatedLocalMacCounts::default(),
            shutdown: CancellationToken::new(),
        };
        let mut originated = OriginatedSet::new();
        let mac = MacAddress::new([0x02, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        apply_report(
            &report_with(100, InstanceState::Ready, Some(mac)),
            &mut originated,
            &runtime,
        )
        .await;
        apply_report(
            &report_with(100, InstanceState::NotReady, None),
            &mut originated,
            &runtime,
        )
        .await;

        assert!(originated.is_empty(), "originated set must be empty");
        assert_eq!(withdraws.lock().await.len(), 1);
    }

    /// `advertise_svi_mac = false` rows must be ignored even when the
    /// dataplane report carries a bridge MAC.
    #[tokio::test]
    async fn advertise_svi_mac_false_is_inert() {
        let instances = instance_table(false);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = drain_responder(rib_rx, captured.clone(), withdraws.clone());

        let runtime = SviRuntime {
            instances,
            rib_tx,
            metrics: BgpMetrics::new(),
            originated_local_mac_counts: OriginatedLocalMacCounts::default(),
            shutdown: CancellationToken::new(),
        };
        let mut originated = OriginatedSet::new();

        apply_report(
            &report_with(100, InstanceState::Ready, Some(MacAddress::new([0xaa; 6]))),
            &mut originated,
            &runtime,
        )
        .await;

        assert!(originated.is_empty());
        assert!(captured.lock().await.is_empty());
    }

    /// Counter accounting: an Inject bumps the per-VNI counter; the
    /// matching Withdraw decrements it back to zero.
    #[tokio::test]
    async fn counter_round_trips_through_inject_and_withdraw() {
        let instances = instance_table(true);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = drain_responder(rib_rx, captured.clone(), withdraws.clone());

        let counts = OriginatedLocalMacCounts::default();
        let runtime = SviRuntime {
            instances,
            rib_tx,
            metrics: BgpMetrics::new(),
            originated_local_mac_counts: counts.clone(),
            shutdown: CancellationToken::new(),
        };
        let mut originated = OriginatedSet::new();
        let mac = MacAddress::new([0x02, 0x12, 0x34, 0x56, 0x78, 0x9a]);

        apply_report(
            &report_with(100, InstanceState::Ready, Some(mac)),
            &mut originated,
            &runtime,
        )
        .await;
        assert_eq!(counts.count(vni(100)), 1, "counter must reflect the Inject");

        apply_report(
            &report_with(100, InstanceState::NotReady, None),
            &mut originated,
            &runtime,
        )
        .await;
        assert_eq!(counts.count(vni(100)), 0, "counter must clear on Withdraw");
    }

    /// ADR-0056: when the bridge MAC is listed in
    /// `[[evpn_instances]].sticky_macs`, the originated SVI Type 2
    /// must carry the RFC 7432 §15.4 MAC Mobility extended community
    /// with `sticky=true`. Without this, the ADR's "operators can
    /// mark the SVI MAC sticky via `sticky_macs`" guarantee is a lie.
    #[tokio::test]
    async fn sticky_macs_marks_originated_svi_mac() {
        use std::collections::BTreeSet;

        use rustbgpd_wire::PathAttribute;

        let svi_mac = MacAddress::new([0x02, 0xab, 0xcd, 0xef, 0x00, 0x01]);
        // Single instance with advertise_svi_mac=true AND the bridge
        // MAC pinned sticky.
        let inst = instance(100, true).with_sticky_macs(BTreeSet::from([svi_mac]));
        let mut t = EvpnInstanceTable::new();
        t.insert(inst).unwrap();
        let instances = Arc::new(t);

        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = drain_responder(rib_rx, captured.clone(), withdraws.clone());

        let runtime = SviRuntime {
            instances,
            rib_tx,
            metrics: BgpMetrics::new(),
            originated_local_mac_counts: OriginatedLocalMacCounts::default(),
            shutdown: CancellationToken::new(),
        };
        let mut originated = OriginatedSet::new();

        apply_report(
            &report_with(100, InstanceState::Ready, Some(svi_mac)),
            &mut originated,
            &runtime,
        )
        .await;

        let injects = captured.lock().await;
        let route = injects.first().expect("Inject must fire on first Ready");
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v),
                _ => None,
            })
            .expect("originated SVI route must carry ExtendedCommunities");
        let mobility = extcomms
            .iter()
            .find_map(|ec| ec.as_mac_mobility())
            .expect("sticky SVI MAC must emit a MAC Mobility extcomm");
        assert!(
            mobility.0,
            "sticky_macs entry must propagate to MAC Mobility sticky bit"
        );
        assert_eq!(mobility.1, 0, "no contender — seq must stay at 0");
    }
}
