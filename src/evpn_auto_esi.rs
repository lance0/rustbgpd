//! Runtime readiness probe for `esi = "auto-lacp"` Ethernet Segments.
//!
//! Config validation never reads the kernel. This probe reads each
//! named 802.3ad bond's LACP partner every [`PROBE_INTERVAL`] and hands
//! the derived RFC 7432 §5 type 1 ESIs to
//! [`EvpnRuntimeReloadApply::publish_auto_lacp_round`], which publishes
//! the complete round into the daemon's readiness table
//! ([`crate::config::AutoLacpEsis`]) and re-converges under the EVPN
//! apply lock. A bond without a usable partner is not ready: its
//! segment resolves to no runtime segment and originates nothing. When
//! a derived ESI appears, disappears, or changes (CE replaced), the
//! re-converge adds, deletes, or deletes-then-adds the segment —
//! withdrawing the old ES/EAD routes before originating under the new
//! ESI.
//!
//! Readiness transitions are logged with a stable reason code
//! (`no_partner`, `down`, `not_lacp_mode`, …) and published as the
//! `evpn_es_auto_esi_state{interface, state}` state set.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::EthernetSegmentIdentifier;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::evpn_runtime_converger::EvpnRuntimeReloadApply;

/// Partner-change detection latency bound. LACP fast rate is 1 s and
/// slow rate 30 s, so this is never the limiting factor.
const PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// Ceiling on the startup probe. Each bond read is bounded by the
/// netlink reply timeout; this caps the whole round so startup never
/// waits on many slow bonds. Bonds not read in time start not ready
/// and the periodic probe picks them up.
pub(crate) const STARTUP_PROBE_BOUND: Duration = Duration::from_secs(2);

/// One bond read: the derived ESI, or `(reason code, detail)`.
pub(crate) type ProbeResult = Result<EthernetSegmentIdentifier, (&'static str, String)>;

/// The bonds a round of reads found ready, with their derived ESIs —
/// the snapshot handed to the publish step.
pub(crate) fn ready(
    results: &BTreeMap<String, ProbeResult>,
) -> BTreeMap<String, EthernetSegmentIdentifier> {
    results
        .iter()
        .filter_map(|(bond, result)| result.as_ref().ok().map(|esi| (bond.clone(), *esi)))
        .collect()
}

/// Last reported status per bond, for transition logging and the
/// readiness gauge.
pub(crate) struct AutoEsiProbe {
    last: BTreeMap<String, ProbeResult>,
    metrics: BgpMetrics,
}

impl AutoEsiProbe {
    pub(crate) fn new(metrics: BgpMetrics) -> Self {
        Self {
            last: BTreeMap::new(),
            metrics,
        }
    }

    /// Settle each bond's status after the round was published, log the
    /// transitions, and return them. A failed re-converge settles every
    /// bond in the round as `reconverge_failed`, whatever its read: the
    /// runtime has not moved, so a segment whose ESI was just unpublished
    /// may still originate under its previous ESI. Every other not-ready
    /// reason is therefore reported only once the runtime matches it. A
    /// bond is Ready only when its read succeeded, its derived ESI did not
    /// collide (`esi_collision`), and the re-converge (if one ran)
    /// succeeded. Each transition sets the bond's `evpn_es_auto_esi_state`
    /// series. Bonds no longer read are forgotten and their series removed.
    pub(crate) fn report(
        &mut self,
        results: BTreeMap<String, ProbeResult>,
        collided: &BTreeSet<String>,
        reconverge_error: Option<&str>,
    ) -> Vec<(String, ProbeResult)> {
        let metrics = &self.metrics;
        self.last.retain(|bond, _| {
            let keep = results.contains_key(bond);
            if !keep {
                metrics.remove_evpn_es_auto_esi_state(bond);
            }
            keep
        });
        let mut transitions = Vec::new();
        for (bond, read) in results {
            let status = match (read, reconverge_error) {
                (read, Some(error)) => {
                    let read = match read {
                        Ok(esi) => format!("derived ESI {esi}"),
                        Err((reason, _)) => reason.to_string(),
                    };
                    Err((
                        "reconverge_failed",
                        format!("{error}; bond read: {read}; retrying"),
                    ))
                }
                (Ok(esi), None) if collided.contains(&bond) => Err((
                    "esi_collision",
                    format!("derived ESI {esi} matches another segment's ESI"),
                )),
                (Ok(esi), None) => Ok(esi),
                (Err(reason), None) => Err(reason),
            };
            if self.last.get(&bond) == Some(&status) {
                continue;
            }
            match &status {
                Ok(esi) => info!(
                    interface = %bond,
                    esi = %esi,
                    "auto-lacp Ethernet Segment ready: originating under the RFC 7432 type 1 ESI derived from the LACP partner"
                ),
                Err((reason, detail)) => warn!(
                    interface = %bond,
                    reason,
                    detail = %detail,
                    "auto-lacp Ethernet Segment not ready"
                ),
            }
            let state = status
                .as_ref()
                .map_or_else(|(reason, _)| *reason, |_| "ready");
            self.metrics.set_evpn_es_auto_esi_state(&bond, state);
            self.last.insert(bond.clone(), status.clone());
            transitions.push((bond, status));
        }
        transitions
    }
}

/// Read every bond on the blocking pool, so a slow netlink reply never
/// stalls a runtime worker. Each read is bounded by the netlink reply
/// timeout and the caller awaits one round before starting the next, so
/// a wedged netlink path holds at most one blocking thread, briefly.
pub(crate) async fn read_bonds(interfaces: BTreeSet<String>) -> BTreeMap<String, ProbeResult> {
    let names = interfaces.clone();
    tokio::task::spawn_blocking(move || {
        names
            .into_iter()
            .map(|name| {
                let result = read_kernel(&name);
                (name, result)
            })
            .collect()
    })
    .await
    .unwrap_or_else(|error| {
        let detail = format!("bond read task failed: {error}");
        interfaces
            .into_iter()
            .map(|name| (name, Err(("netlink_error", detail.clone()))))
            .collect()
    })
}

/// Read one bond from the kernel.
#[cfg(target_os = "linux")]
fn read_kernel(name: &str) -> ProbeResult {
    rustbgpd_evpn_linux::read_bond_lacp_partner(name)
        .map(|p| rustbgpd_evpn::lacp_type1_esi(p.system_mac, p.port_key))
        .map_err(|e| (e.code(), e.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn read_kernel(_name: &str) -> ProbeResult {
    Err((
        "unsupported",
        "LACP partner discovery requires Linux".to_string(),
    ))
}

/// Publish one round of bond reads and settle the probe against it.
/// Reporting and series removal use the bond set the locked publish
/// settled, so a bond a reload removed during the read loses its series
/// in this round. Returns whether the next round must retry the
/// re-converge.
pub(crate) async fn run_round(
    probe: &mut AutoEsiProbe,
    reload_apply: &EvpnRuntimeReloadApply,
    mut results: BTreeMap<String, ProbeResult>,
    retry: bool,
) -> bool {
    let round = reload_apply
        .publish_auto_lacp_round(ready(&results), retry)
        .await;
    results.retain(|bond, _| round.configured.contains(bond));
    let reconverge_error = round.result.as_ref().err().map(|e| format!("{e:?}"));
    probe.report(results, &round.collided, reconverge_error.as_deref());
    match round.result {
        Ok(None) => retry,
        Ok(Some(response)) => {
            info!(
                outcome = response.outcome,
                message = %response.message,
                "auto-lacp ESI change re-converged"
            );
            false
        }
        Err(error) => {
            warn!(
                ?error,
                "auto-lacp ESI change failed to re-converge; retrying"
            );
            true
        }
    }
}

/// Starts the probe the first time it is needed, at startup or live, and
/// never after shutdown cancelled it.
#[derive(Clone)]
pub(crate) struct AutoEsiProbeStarter {
    pending: Arc<Mutex<Option<AutoEsiProbe>>>,
    shutdown: CancellationToken,
}

impl AutoEsiProbeStarter {
    pub(crate) fn new(probe: AutoEsiProbe, shutdown: CancellationToken) -> Self {
        Self {
            pending: Arc::new(Mutex::new(Some(probe))),
            shutdown,
        }
    }

    #[cfg(test)]
    pub(crate) fn started(&self) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    }

    /// Spawn the probe unless it already runs. A probe spawned while
    /// shutdown cancels the token exits on its first poll.
    pub(crate) fn start(&self, reload_apply: &EvpnRuntimeReloadApply) {
        let probe = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(probe) = probe {
            drop(spawn(probe, reload_apply.clone(), self.shutdown.clone()));
        }
    }
}

/// Run the probe until `shutdown`. Each round reads bonds outside the
/// apply lock, then publishes and re-converges as one locked operation.
/// A failed re-converge is retried on the next round.
fn spawn(
    mut probe: AutoEsiProbe,
    reload_apply: EvpnRuntimeReloadApply,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PROBE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut retry = false;
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            let interfaces = reload_apply.committed_auto_lacp_interfaces();
            let results = tokio::select! {
                () = shutdown.cancelled() => return,
                results = read_bonds(interfaces) => results,
            };
            retry = run_round(&mut probe, &reload_apply, results, retry).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esi(last: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([1, 2, 0, 0, 0, 0, last, 0, 7, 0])
    }

    fn round(result: Option<ProbeResult>) -> BTreeMap<String, ProbeResult> {
        result
            .map(|r| ("bond0".to_string(), r))
            .into_iter()
            .collect()
    }

    fn not_ready() -> ProbeResult {
        Err(("no_partner", "bond has no LACP partner yet".to_string()))
    }

    #[test]
    fn ready_is_reported_only_after_collision_and_reconverge_settle() {
        let mut probe = AutoEsiProbe::new(BgpMetrics::new());
        let none = BTreeSet::new();
        let codes = |t: Vec<(String, ProbeResult)>| -> Vec<Result<EthernetSegmentIdentifier, &'static str>> {
            t.into_iter().map(|(_, s)| s.map_err(|(code, _)| code)).collect()
        };

        assert_eq!(
            codes(probe.report(round(Some(not_ready())), &none, None)),
            vec![Err("no_partner")]
        );
        // Read succeeded but the re-converge failed: not Ready yet.
        assert_eq!(
            codes(probe.report(round(Some(Ok(esi(1)))), &none, Some("injected"))),
            vec![Err("reconverge_failed")]
        );
        // Read succeeded but the derived ESI collides: not Ready.
        let collided = BTreeSet::from(["bond0".to_string()]);
        assert_eq!(
            codes(probe.report(round(Some(Ok(esi(1)))), &collided, None)),
            vec![Err("esi_collision")]
        );
        // A failed re-converge outranks a not-ready read: the runtime has
        // not withdrawn the segment yet.
        assert_eq!(
            codes(probe.report(round(Some(not_ready())), &none, Some("injected"))),
            vec![Err("reconverge_failed")]
        );
        // Published cleanly: Ready, reported once.
        assert_eq!(
            codes(probe.report(round(Some(Ok(esi(1)))), &none, None)),
            vec![Ok(esi(1))]
        );
        assert_eq!(
            codes(probe.report(round(Some(Ok(esi(1)))), &none, None)),
            vec![]
        );
        assert_eq!(codes(probe.report(round(None), &none, None)), vec![]);
        assert_eq!(
            ready(&round(Some(Ok(esi(2))))),
            BTreeMap::from([("bond0".to_string(), esi(2))])
        );
    }

    /// The `evpn_es_auto_esi_state` series set to 1 for `interface`, or
    /// `None` when it has no series; panics if more than one reads 1.
    fn gauge_state(metrics: &BgpMetrics, interface: &str) -> Option<String> {
        let text = crate::test_support::gather_metrics_text(metrics);
        let prefix = format!("evpn_es_auto_esi_state{{interface=\"{interface}\",state=\"");
        let mut series = 0;
        let mut set = Vec::new();
        for rest in text.lines().filter_map(|line| line.strip_prefix(&prefix)) {
            series += 1;
            let (state, value) = rest.split_once("\"} ").unwrap();
            if value == "1" {
                set.push(state.to_string());
            }
        }
        assert!(set.len() <= 1, "more than one state set: {set:?}");
        (series > 0).then(|| set.pop().unwrap_or_default())
    }

    #[test]
    fn readiness_gauge_follows_the_settled_status_and_is_removed_with_the_segment() {
        let metrics = BgpMetrics::new();
        let mut probe = AutoEsiProbe::new(metrics.clone());
        let none = BTreeSet::new();

        probe.report(round(Some(not_ready())), &none, None);
        assert_eq!(
            gauge_state(&metrics, "bond0").as_deref(),
            Some("no_partner")
        );

        // A clean read whose re-converge failed is still not ready.
        probe.report(round(Some(Ok(esi(1)))), &none, Some("injected"));
        assert_eq!(
            gauge_state(&metrics, "bond0").as_deref(),
            Some("reconverge_failed")
        );

        probe.report(round(Some(Ok(esi(1)))), &none, None);
        assert_eq!(gauge_state(&metrics, "bond0").as_deref(), Some("ready"));

        probe.report(round(Some(not_ready())), &none, None);
        assert_eq!(
            gauge_state(&metrics, "bond0").as_deref(),
            Some("no_partner")
        );

        // The segment left the config: its series go with it.
        probe.report(round(None), &none, None);
        assert_eq!(gauge_state(&metrics, "bond0"), None);
    }

    /// Every reason a bond read or a publish can report is a state the
    /// gauge publishes; an unlisted one would leave every series at 0.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_not_ready_reason_is_a_published_gauge_state() {
        use rustbgpd_evpn_linux::LacpPartnerError;
        // Exhaustive: a new error variant fails to compile here until it
        // is listed, and so reaches the vocabulary check below.
        let listed = |e: &LacpPartnerError| -> &'static str {
            match e {
                LacpPartnerError::NotFound
                | LacpPartnerError::NotBond
                | LacpPartnerError::NotLacpMode
                | LacpPartnerError::Down
                | LacpPartnerError::NoActiveAggregator
                | LacpPartnerError::NoPartner
                | LacpPartnerError::Io(_) => e.code(),
            }
        };
        let states = rustbgpd_telemetry::evpn_es_auto_esi_states();
        let errors = [
            LacpPartnerError::NotFound,
            LacpPartnerError::NotBond,
            LacpPartnerError::NotLacpMode,
            LacpPartnerError::Down,
            LacpPartnerError::NoActiveAggregator,
            LacpPartnerError::NoPartner,
            LacpPartnerError::Io(std::io::Error::other("x")),
        ];
        let reasons = errors.iter().map(listed).chain([
            "esi_collision",
            "reconverge_failed",
            "unsupported",
            "ready",
        ]);
        for reason in reasons {
            assert!(states.contains(&reason), "{reason} is not a gauge state");
        }
    }

    #[tokio::test]
    async fn read_bonds_reports_a_missing_bond_as_not_found() {
        let results = read_bonds(BTreeSet::from(["rbgp-absent0".to_string()])).await;
        assert!(matches!(
            results.get("rbgp-absent0"),
            Some(Err(("not_found" | "unsupported", _)))
        ));
    }
}
