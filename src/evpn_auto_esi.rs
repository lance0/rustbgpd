//! Runtime readiness probe for `esi = "auto-lacp"` Ethernet Segments.
//!
//! Config validation never reads the kernel. This probe reads each
//! named 802.3ad bond's LACP partner every [`PROBE_INTERVAL`] and
//! publishes the derived RFC 7432 §5 type 1 ESI into the config
//! readiness snapshot ([`crate::config::set_auto_lacp_esi`]). A bond
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

use crate::config::set_auto_lacp_esi;
use crate::evpn_runtime_converger::EvpnRuntimeReloadApply;

/// Partner-change detection latency bound. LACP fast rate is 1 s and
/// slow rate 30 s, so this is never the limiting factor.
const PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// One bond read: the derived ESI, or `(reason code, detail)`.
pub(crate) type ProbeResult = Result<EthernetSegmentIdentifier, (&'static str, String)>;

/// Last observed result per bond, for transition logging.
#[derive(Default)]
pub(crate) struct AutoEsiProbe {
    last: BTreeMap<String, ProbeResult>,
}

impl AutoEsiProbe {
    /// Read `interfaces` with `read`, publish into the readiness
    /// snapshot, and forget bonds that left the config. Returns whether
    /// any derived ESI changed (the caller must then re-converge).
    pub(crate) fn probe(
        &mut self,
        interfaces: &BTreeSet<String>,
        read: impl Fn(&str) -> ProbeResult,
    ) -> bool {
        let mut changed = false;
        self.last.retain(|name, _| {
            let keep = interfaces.contains(name);
            if !keep {
                changed |= set_auto_lacp_esi(name, None);
            }
            keep
        });
        for name in interfaces {
            let result = read(name);
            if self.last.get(name) != Some(&result) {
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
            changed |= set_auto_lacp_esi(name, result.as_ref().ok().copied());
            self.last.insert(name.clone(), result);
        }
        changed
    }
}

/// Read one bond from the kernel.
#[cfg(target_os = "linux")]
pub(crate) fn read_kernel(name: &str) -> ProbeResult {
    rustbgpd_evpn_linux::read_bond_lacp_partner(name)
        .map(|p| rustbgpd_evpn::lacp_type1_esi(p.system_mac, p.port_key))
        .map_err(|e| (e.code(), e.to_string()))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_kernel(_name: &str) -> ProbeResult {
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
            pending |= probe.probe(&interfaces, read_kernel);
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

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    fn not_ready(_: &str) -> ProbeResult {
        Err(("no_partner", "bond has no LACP partner yet".to_string()))
    }

    #[test]
    fn readiness_transitions_report_change_only_when_the_esi_moves() {
        let mut probe = AutoEsiProbe::default();
        let bond = set(&["rbgp-probe0"]);
        assert!(!probe.probe(&bond, not_ready), "NotReady publishes nothing");
        assert!(probe.probe(&bond, |_| Ok(esi(1))), "became Ready");
        assert!(!probe.probe(&bond, |_| Ok(esi(1))), "steady Ready");
        assert!(probe.probe(&bond, |_| Ok(esi(2))), "partner replaced");
        assert!(probe.probe(&bond, not_ready), "partner lost");
        assert!(probe.probe(&bond, |_| Ok(esi(2))), "Ready again");
        assert!(
            probe.probe(&set(&[]), not_ready),
            "a bond leaving the config clears its ESI"
        );
        assert!(!probe.probe(&set(&[]), not_ready));
    }
}
