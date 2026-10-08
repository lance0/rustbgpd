//! Runtime readiness probe for `esi = "auto-lacp"` Ethernet Segments.
//!
//! Config validation never reads the kernel. This probe reads each
//! named 802.3ad bond's LACP partner every [`PROBE_INTERVAL`] and
//! publishes the derived RFC 7432 §5 type 1 ESI into the daemon's
//! readiness table ([`crate::config::AutoLacpEsis`]). A bond
//! without a usable partner is not ready: its segment resolves to no
//! runtime segment and originates nothing. When a derived ESI appears,
//! disappears, or changes (CE replaced), the probe re-converges the
//! committed config through the ADR-0063 runtime apply, which adds,
//! deletes, or deletes-then-adds the segment — withdrawing the old
//! ES/EAD routes before originating under the new ESI.
//!
//! Readiness transitions are logged with a stable reason code
//! (`no_partner`, `down`, `not_lacp_mode`, …).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use rustbgpd_wire::EthernetSegmentIdentifier;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::AutoLacpEsis;
use crate::evpn_runtime_converger::EvpnRuntimeReloadApply;

/// Partner-change detection latency bound. LACP fast rate is 1 s and
/// slow rate 30 s, so this is never the limiting factor.
const PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// One bond read: the derived ESI, or `(reason code, detail)`.
pub(crate) type ProbeResult = Result<EthernetSegmentIdentifier, (&'static str, String)>;

/// The probe's writer handle on the readiness table, plus the last
/// observed result per bond for transition logging.
pub(crate) struct AutoEsiProbe {
    esis: AutoLacpEsis,
    last: BTreeMap<String, ProbeResult>,
}

impl AutoEsiProbe {
    pub(crate) fn new(esis: AutoLacpEsis) -> Self {
        Self {
            esis,
            last: BTreeMap::new(),
        }
    }

    /// Publish one round of bond reads into the readiness table and
    /// forget bonds that left the config (`results` holds exactly the
    /// configured bonds). Returns whether any derived ESI changed (the
    /// caller must then re-converge).
    pub(crate) fn apply(&mut self, results: BTreeMap<String, ProbeResult>) -> bool {
        let mut changed = false;
        let esis = &self.esis;
        self.last.retain(|name, _| {
            let keep = results.contains_key(name);
            if !keep {
                changed |= esis.set(name, None);
            }
            keep
        });
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
            changed |= self.esis.set(&name, result.as_ref().ok().copied());
            self.last.insert(name, result);
        }
        changed
    }
}

/// Read every bond on the blocking pool, so a slow or hung netlink
/// reply never stalls a runtime worker. The caller awaits the read
/// before issuing another, so a hung reply holds at most one blocking
/// thread.
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

/// Run the probe until `shutdown`, re-converging after every change.
/// A failed re-converge is retried on the next tick.
pub(crate) fn spawn(
    mut probe: AutoEsiProbe,
    reload_apply: EvpnRuntimeReloadApply,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PROBE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut pending = false;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            let interfaces = reload_apply.committed_auto_lacp_interfaces();
            pending |= probe.apply(read_bonds(interfaces).await);
            if !pending {
                continue;
            }
            match reload_apply.reconverge_committed().await {
                Ok(response) => {
                    pending = false;
                    info!(
                        outcome = response.outcome,
                        message = %response.message,
                        "auto-lacp ESI change re-converged"
                    );
                }
                Err(error) => warn!(
                    ?error,
                    "auto-lacp ESI change failed to re-converge; retrying"
                ),
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
    fn readiness_transitions_report_change_only_when_the_esi_moves() {
        // The probe's own table: nothing outside this test can see it.
        let esis = AutoLacpEsis::default();
        let mut probe = AutoEsiProbe::new(esis.clone());
        assert!(
            !probe.apply(round(Some(not_ready()))),
            "not ready publishes nothing"
        );
        assert!(probe.apply(round(Some(Ok(esi(1))))), "became ready");
        assert!(!probe.apply(round(Some(Ok(esi(1))))), "steady ready");
        assert!(probe.apply(round(Some(Ok(esi(2))))), "partner replaced");
        assert!(
            !esis.set("bond0", Some(esi(2))),
            "the shared handle sees the write"
        );
        assert!(probe.apply(round(Some(not_ready()))), "partner lost");
        assert!(probe.apply(round(Some(Ok(esi(2))))), "ready again");
        assert!(
            probe.apply(round(None)),
            "a bond leaving the config clears its ESI"
        );
        assert!(!probe.apply(round(None)));
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
