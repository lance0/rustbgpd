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
//! (`no_partner`, `down`, `not_lacp_mode`, …).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

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

/// Last observed result per bond, for transition logging.
#[derive(Default)]
pub(crate) struct AutoEsiProbe {
    last: BTreeMap<String, ProbeResult>,
}

impl AutoEsiProbe {
    /// Log readiness transitions for one round of bond reads, forget
    /// bonds no longer read, and return the ready bonds' ESIs.
    pub(crate) fn observe(
        &mut self,
        results: BTreeMap<String, ProbeResult>,
    ) -> BTreeMap<String, EthernetSegmentIdentifier> {
        self.last.retain(|name, _| results.contains_key(name));
        let mut ready = BTreeMap::new();
        for (name, result) in results {
            if self.last.get(&name) != Some(&result) {
                match &result {
                    Ok(esi) => info!(
                        interface = %name,
                        esi = %esi,
                        "auto-lacp Ethernet Segment ready: derived RFC 7432 type 1 ESI from the LACP partner"
                    ),
                    Err((reason, detail)) => warn!(
                        interface = %name,
                        reason,
                        detail = %detail,
                        "auto-lacp Ethernet Segment not ready; originating nothing for it"
                    ),
                }
            }
            if let Ok(esi) = &result {
                ready.insert(name.clone(), *esi);
            }
            self.last.insert(name, result);
        }
        ready
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

/// Run the probe until `shutdown`. Each round reads bonds outside the
/// apply lock, then publishes and re-converges as one locked operation.
/// A failed re-converge is retried on the next round.
pub(crate) fn spawn(
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
                () = shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            let interfaces = reload_apply.committed_auto_lacp_interfaces();
            let results = tokio::select! {
                () = shutdown.cancelled() => return,
                results = read_bonds(interfaces) => results,
            };
            let ready = probe.observe(results);
            match reload_apply.publish_auto_lacp_round(ready, retry).await {
                Ok(None) => {}
                Ok(Some(response)) => {
                    retry = false;
                    info!(
                        outcome = response.outcome,
                        message = %response.message,
                        "auto-lacp ESI change re-converged"
                    );
                }
                Err(error) => {
                    retry = true;
                    warn!(
                        ?error,
                        "auto-lacp ESI change failed to re-converge; retrying"
                    );
                }
            }
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
    fn observe_returns_only_ready_bonds() {
        let mut probe = AutoEsiProbe::default();
        assert!(probe.observe(round(Some(not_ready()))).is_empty());
        assert_eq!(
            probe.observe(round(Some(Ok(esi(1))))),
            BTreeMap::from([("bond0".to_string(), esi(1))])
        );
        assert!(probe.observe(round(None)).is_empty());
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
