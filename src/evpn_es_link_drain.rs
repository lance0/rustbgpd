//! ADR-0085 link-driven Ethernet Segment drain coordinator
//! (decisions 1 + 3).
//!
//! Consumes two watch channels — the resolved `[[ethernet_segments]]`
//! `interface` bindings (republished whenever the committed EVPN
//! config advances) and the slice-1 link carrier projection
//! (`rustbgpd_evpn_linux::link_carrier`) — and drives the `Link`
//! drain reason through the same [`apply_ethernet_segment_drain`]
//! primitive (and therefore the same EVPN runtime apply lock) the
//! ADR-0084 RPC uses:
//!
//! - **Carrier down → drain immediately.** A bound name absent from
//!   the kernel projection counts as down (fail-closed), as does a
//!   monitor that cannot run at all (spawn failure, non-Linux build).
//! - **Carrier up → hold `recovery_delay_secs`, then undrain.** The
//!   hold re-arms on every up edge, so a flapping circuit stays
//!   drained until it holds carrier for the full window (decision 3).
//! - **Startup / binding change applies the first probe directly** —
//!   no hold-off: an ES whose AC is down at boot starts
//!   drained(Link); up at boot originates immediately; rebinding to a
//!   different link re-evaluates against the new link's state
//!   immediately (decision 1).
//! - **Binding removed → the `Link` reason is dropped**: unbound
//!   segments have no link reason, ever.
//!
//! ## Shape
//!
//! A single owner task wraps a pure planner
//! ([`EsLinkDrainPlanner`]) — the same pure-projection + thin-loop
//! split the slice-1 `CarrierProjection` uses. Recovery hold-offs are
//! a **deadline map polled by this loop** (`sleep_until` the earliest
//! deadline in the `select!`), not per-ES spawned timer tasks: every
//! drain mutation must serialize through the EVPN runtime apply lock
//! and consult binding + carrier state at fire time, and keeping one
//! owner means a firing timer can never race a concurrent binding
//! replace or carrier edge inside this coordinator. Re-arming is a
//! map overwrite; cancellation is a map remove.
//!
//! The kernel monitor is spawned lazily when the first binding
//! appears and dropped (drop-to-stop) when the last one goes, so
//! deployments without bindings pay nothing; a runtime reload that
//! adds the first binding still gets eventing without a restart.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use rustbgpd_wire::EthernetSegmentIdentifier;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::EsLinkBinding;
use crate::evpn_es_drain::{
    EsDrainError, EsDrainReason, EvpnEsDrainState, apply_ethernet_segment_drain,
};
use crate::evpn_originator::EvpnOriginatorRuntimeControl;
use crate::evpn_segment::EvpnSegmentRuntimeControl;

/// Resolved ADR-0085 bindings, keyed by ESI. Published by the daemon
/// at startup and re-published whenever the committed EVPN config
/// advances (SIGHUP / `ApplyEvpnRuntime`).
pub(crate) type EsLinkBindings = Arc<BTreeMap<EthernetSegmentIdentifier, EsLinkBinding>>;

/// Carrier projection consumed by the coordinator. Structurally
/// identical to `rustbgpd_evpn_linux::LinkCarrierMap`; aliased here so
/// the coordinator (and its tests) stay platform-independent — only
/// the kernel feed itself is Linux-gated.
pub(crate) type CarrierMap = Arc<BTreeMap<String, bool>>;

/// Dependency spine for applying `Link` drain mutations — the same
/// arguments the ADR-0084 gRPC hook feeds the shared primitive.
pub(crate) struct EsLinkDrainDeps {
    pub apply_lock: Arc<tokio::sync::Mutex<()>>,
    pub coordinator: Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>>,
    pub drain_state: EvpnEsDrainState,
    pub segment: Option<EvpnSegmentRuntimeControl>,
    pub originator: Option<EvpnOriginatorRuntimeControl>,
}

/// Where carrier state comes from.
pub(crate) enum CarrierFeed {
    /// Lazily spawn and own the slice-1 kernel monitor for the bound
    /// link names (Linux only; elsewhere bound links fail closed to
    /// down).
    Kernel,
    /// Test-injected carrier watch; the watched-name set is whatever
    /// the test publishes.
    #[cfg(test)]
    Injected(watch::Receiver<CarrierMap>),
}

/// Spawn the coordinator task. It exits when `shutdown` is cancelled
/// or the bindings channel closes.
pub(crate) fn spawn(
    bindings_rx: watch::Receiver<EsLinkBindings>,
    feed: CarrierFeed,
    deps: EsLinkDrainDeps,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(bindings_rx, feed, deps, shutdown))
}

async fn run(
    mut bindings_rx: watch::Receiver<EsLinkBindings>,
    feed: CarrierFeed,
    deps: EsLinkDrainDeps,
    shutdown: CancellationToken,
) {
    // Fallback carrier source: keeps the select arm total when no
    // kernel monitor is running. Whatever names it carries are down —
    // fail-closed toward drain (ADR-0085 decision 1).
    let (fallback_tx, fallback_rx) = watch::channel::<CarrierMap>(Arc::new(BTreeMap::new()));
    let mut feed = FeedState::new(feed, fallback_rx);
    let mut planner = EsLinkDrainPlanner::new();

    // First probe: evaluate the initial bindings against the feed's
    // initial projection directly — no hold-off (decision 3 startup).
    let initial = bindings_rx.borrow_and_update().clone();
    feed.sync(watched_links(&initial), &fallback_tx).await;
    let carrier = feed.carrier_rx.borrow_and_update().clone();
    let actions = planner.replace_bindings(initial, &carrier, Instant::now());
    apply_actions(actions, &deps, &mut planner).await;

    loop {
        let deadline = planner.next_deadline();
        let actions = tokio::select! {
            () = shutdown.cancelled() => return,
            changed = bindings_rx.changed() => {
                if changed.is_err() {
                    debug!("ES link binding channel closed; link drain coordinator exiting");
                    return;
                }
                let next = bindings_rx.borrow_and_update().clone();
                feed.sync(watched_links(&next), &fallback_tx).await;
                let carrier = feed.carrier_rx.borrow_and_update().clone();
                planner.replace_bindings(next, &carrier, Instant::now())
            }
            changed = feed.carrier_rx.changed() => {
                if changed.is_err() {
                    // Monitor task died (rtnetlink connection lost).
                    // Fail closed: bound links are down until a
                    // bindings change retries the spawn.
                    warn!(
                        "link carrier monitor stopped; bound Ethernet Segments fail \
                         closed to drained until the next config change"
                    );
                    feed.fail_closed(planner.bound_links(), &fallback_tx);
                }
                let carrier = feed.carrier_rx.borrow_and_update().clone();
                planner.evaluate(&carrier, Instant::now())
            }
            () = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)),
                if deadline.is_some() =>
            {
                planner.fire_due(Instant::now())
            }
        };
        apply_actions(actions, &deps, &mut planner).await;
    }
}

async fn apply_actions(
    actions: Vec<LinkDrainAction>,
    deps: &EsLinkDrainDeps,
    planner: &mut EsLinkDrainPlanner,
) {
    for action in actions {
        let (esi, drained) = match action {
            LinkDrainAction::Drain(esi) => (esi, true),
            LinkDrainAction::Undrain(esi) => (esi, false),
        };
        match apply_ethernet_segment_drain(
            esi,
            EsDrainReason::Link,
            drained,
            &deps.apply_lock,
            &deps.coordinator,
            &deps.drain_state,
            deps.segment.as_ref(),
            deps.originator.as_ref(),
        )
        .await
        {
            Ok(outcome) => {
                if outcome.changed {
                    info!(
                        %esi,
                        drained,
                        composed_drained = outcome.drained,
                        reasons = %format_reasons(&outcome.reasons),
                        "attachment-circuit carrier changed Ethernet Segment link drain"
                    );
                }
            }
            // The ES left the committed config between the bindings
            // publish and this apply — GC already dropped its drain
            // entry; the next bindings publish drops the planner state.
            Err(EsDrainError::UnknownEsi(message)) => {
                debug!(%esi, message, "link drain skipped for unconfigured ESI");
                planner.forget(esi);
            }
            // Actor teardown. Forget the ES so a post-recovery
            // evaluation re-applies from scratch instead of assuming
            // this mutation landed.
            Err(EsDrainError::Unavailable(message)) => {
                warn!(%esi, message, "link drain publish unavailable");
                planner.forget(esi);
            }
        }
    }
}

fn format_reasons(reasons: &BTreeSet<EsDrainReason>) -> String {
    if reasons.is_empty() {
        return "none".to_string();
    }
    reasons
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn watched_links(bindings: &EsLinkBindings) -> BTreeSet<String> {
    bindings
        .values()
        .map(|binding| binding.interface.clone())
        .collect()
}

/// Owns the carrier source: either the lazily-spawned kernel monitor
/// or a test-injected watch. `carrier_rx` is always a live receiver —
/// the fallback channel stands in whenever no monitor runs.
struct FeedState {
    injected: bool,
    #[cfg(target_os = "linux")]
    handle: Option<rustbgpd_evpn_linux::LinkCarrierHandle>,
    carrier_rx: watch::Receiver<CarrierMap>,
}

impl FeedState {
    // Without cfg(test) `CarrierFeed` is a single unit variant and
    // pass-by-value looks gratuitous; the test variant moves a
    // receiver in.
    #[cfg_attr(not(test), expect(clippy::needless_pass_by_value))]
    fn new(feed: CarrierFeed, fallback_rx: watch::Receiver<CarrierMap>) -> Self {
        match feed {
            CarrierFeed::Kernel => Self {
                injected: false,
                #[cfg(target_os = "linux")]
                handle: None,
                carrier_rx: fallback_rx,
            },
            #[cfg(test)]
            CarrierFeed::Injected(carrier_rx) => Self {
                injected: true,
                #[cfg(target_os = "linux")]
                handle: None,
                carrier_rx,
            },
        }
    }

    /// Point `carrier_rx` at the fallback channel with every watched
    /// name down — the fail-closed projection.
    fn fail_closed(&mut self, watched: BTreeSet<String>, fallback_tx: &watch::Sender<CarrierMap>) {
        #[cfg(target_os = "linux")]
        {
            self.handle = None;
        }
        fallback_tx.send_replace(Arc::new(
            watched.into_iter().map(|name| (name, false)).collect(),
        ));
        self.carrier_rx = fallback_tx.subscribe();
    }

    /// Reconcile the carrier source with the bound link-name set:
    /// spawn the kernel monitor when the first binding appears,
    /// replace its watched set on change, drop it (drop-to-stop) when
    /// the last binding goes.
    async fn sync(&mut self, watched: BTreeSet<String>, fallback_tx: &watch::Sender<CarrierMap>) {
        if self.injected {
            return;
        }
        if watched.is_empty() {
            #[cfg(target_os = "linux")]
            {
                if self.handle.take().is_some() {
                    info!(
                        "last Ethernet Segment interface binding removed; link carrier monitor stopped"
                    );
                }
            }
            fallback_tx.send_replace(Arc::new(BTreeMap::new()));
            self.carrier_rx = fallback_tx.subscribe();
            return;
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(handle) = self.handle.as_ref() {
                if handle.replace_watched_links(watched.clone()).await {
                    return;
                }
                warn!("link carrier monitor exited; respawning");
                self.handle = None;
            }
            match rustbgpd_evpn_linux::spawn_link_carrier_monitor(watched.clone()).await {
                Ok(handle) => {
                    info!(
                        links = %watched.iter().cloned().collect::<Vec<_>>().join(","),
                        "link carrier monitor started for Ethernet Segment interface bindings"
                    );
                    self.carrier_rx = handle.subscribe();
                    self.handle = Some(handle);
                }
                Err(error) => {
                    warn!(
                        %error,
                        "link carrier monitor failed to start; bound Ethernet Segments \
                         fail closed to drained until the next config change"
                    );
                    self.fail_closed(watched, fallback_tx);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            warn!(
                "Ethernet Segment interface bindings require Linux rtnetlink; bound \
                 segments fail closed to drained on this platform"
            );
            self.fail_closed(watched, fallback_tx);
        }
    }
}

/// One requested `Link`-reason mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkDrainAction {
    Drain(EthernetSegmentIdentifier),
    Undrain(EthernetSegmentIdentifier),
}

/// Pure decision core: bindings + last-applied carrier + pending
/// recovery deadlines in, drain actions out. No clocks, no channels —
/// callers pass `Instant`s — so the hold-off semantics are unit-tested
/// without the async loop.
struct EsLinkDrainPlanner {
    bindings: EsLinkBindings,
    /// Last carrier value acted on, per bound ES. Absence means the
    /// next evaluation applies directly (startup / new or changed
    /// binding / failed apply) — the no-hold-off path.
    tracked: BTreeMap<EthernetSegmentIdentifier, bool>,
    /// Armed recovery hold-offs (decision 3).
    pending: BTreeMap<EthernetSegmentIdentifier, Instant>,
}

impl EsLinkDrainPlanner {
    fn new() -> Self {
        Self {
            bindings: Arc::new(BTreeMap::new()),
            tracked: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    fn bound_links(&self) -> BTreeSet<String> {
        watched_links(&self.bindings)
    }

    /// Replace the binding set. Removed bindings drop their `Link`
    /// reason (unbound segments never hold one); added or changed
    /// bindings are re-evaluated against `carrier` immediately —
    /// direct application, no hold-off (decision 1).
    fn replace_bindings(
        &mut self,
        next: EsLinkBindings,
        carrier: &BTreeMap<String, bool>,
        now: Instant,
    ) -> Vec<LinkDrainAction> {
        let mut actions = Vec::new();
        for (esi, old) in self.bindings.iter() {
            match next.get(esi) {
                None => {
                    self.tracked.remove(esi);
                    self.pending.remove(esi);
                    actions.push(LinkDrainAction::Undrain(*esi));
                }
                Some(new) if *new != *old => {
                    // Interface or hold-off changed: forget history so
                    // the evaluation below applies the new link's
                    // state directly.
                    self.tracked.remove(esi);
                    self.pending.remove(esi);
                }
                Some(_) => {}
            }
        }
        self.bindings = next;
        let mut evaluated = self.evaluate(carrier, now);
        actions.append(&mut evaluated);
        actions
    }

    /// Fold a carrier projection. Tracked ESes act on edges (down →
    /// drain now; up → arm/re-arm the hold-off, or undrain at zero
    /// delay); untracked ESes apply the state directly. A bound name
    /// the projection does not carry yet is skipped — the feed
    /// guarantees a projection containing every watched name follows
    /// (kernel walk, fallback map, or test publish), and acting on a
    /// stale map would impose a spurious hold-off on a healthy link.
    fn evaluate(&mut self, carrier: &BTreeMap<String, bool>, now: Instant) -> Vec<LinkDrainAction> {
        let mut actions = Vec::new();
        for (esi, binding) in self.bindings.iter() {
            let Some(&up) = carrier.get(&binding.interface) else {
                continue;
            };
            match self.tracked.get(esi).copied() {
                Some(prev) if prev == up => {}
                Some(_) => {
                    self.tracked.insert(*esi, up);
                    if up {
                        if binding.recovery_delay.is_zero() {
                            self.pending.remove(esi);
                            actions.push(LinkDrainAction::Undrain(*esi));
                        } else {
                            // Re-arm on EVERY up edge — flap damping
                            // (decision 3).
                            self.pending.insert(*esi, now + binding.recovery_delay);
                        }
                    } else {
                        // Down is always immediate; cancel any
                        // recovery in flight.
                        self.pending.remove(esi);
                        actions.push(LinkDrainAction::Drain(*esi));
                    }
                }
                None => {
                    // First probe for this binding: apply directly,
                    // no hold-off (decision 3 startup rule).
                    self.tracked.insert(*esi, up);
                    self.pending.remove(esi);
                    actions.push(if up {
                        LinkDrainAction::Undrain(*esi)
                    } else {
                        LinkDrainAction::Drain(*esi)
                    });
                }
            }
        }
        actions
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().min().copied()
    }

    /// Release every hold-off whose deadline has passed. Carrier is
    /// necessarily still up for these — a down edge would have
    /// cancelled the entry.
    fn fire_due(&mut self, now: Instant) -> Vec<LinkDrainAction> {
        let due: Vec<EthernetSegmentIdentifier> = self
            .pending
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(esi, _)| *esi)
            .collect();
        due.into_iter()
            .map(|esi| {
                self.pending.remove(&esi);
                LinkDrainAction::Undrain(esi)
            })
            .collect()
    }

    /// Drop per-ES history after a failed apply so the next
    /// evaluation re-applies directly instead of assuming the failed
    /// mutation landed.
    fn forget(&mut self, esi: EthernetSegmentIdentifier) {
        self.tracked.remove(&esi);
        self.pending.remove(&esi);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::evpn_es_drain::EsDrainReason;

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn binding(interface: &str, delay_secs: u64) -> EsLinkBinding {
        EsLinkBinding {
            interface: interface.to_string(),
            recovery_delay: Duration::from_secs(delay_secs),
        }
    }

    fn bindings(entries: &[(u8, &str, u64)]) -> EsLinkBindings {
        Arc::new(
            entries
                .iter()
                .map(|(seed, interface, delay)| (esi(*seed), binding(interface, *delay)))
                .collect(),
        )
    }

    fn carrier(entries: &[(&str, bool)]) -> BTreeMap<String, bool> {
        entries
            .iter()
            .map(|(name, up)| ((*name).to_string(), *up))
            .collect()
    }

    // ── planner unit tests (pure hold-off semantics) ────────────

    #[tokio::test(start_paused = true)]
    async fn first_probe_applies_directly_without_holdoff() {
        let now = Instant::now();
        let mut planner = EsLinkDrainPlanner::new();
        // AC down at boot → drained(Link) immediately.
        let actions = planner.replace_bindings(
            bindings(&[(1, "es0", 30)]),
            &carrier(&[("es0", false)]),
            now,
        );
        assert_eq!(actions, vec![LinkDrainAction::Drain(esi(1))]);
        assert!(planner.next_deadline().is_none(), "no hold-off at startup");

        // AC up at boot → originate immediately (undrain is a no-op).
        let mut planner = EsLinkDrainPlanner::new();
        let actions =
            planner.replace_bindings(bindings(&[(1, "es0", 30)]), &carrier(&[("es0", true)]), now);
        assert_eq!(actions, vec![LinkDrainAction::Undrain(esi(1))]);
        assert!(planner.next_deadline().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn down_is_immediate_and_recovery_waits_for_the_holdoff() {
        let now = Instant::now();
        let mut planner = EsLinkDrainPlanner::new();
        let _ =
            planner.replace_bindings(bindings(&[(1, "es0", 30)]), &carrier(&[("es0", true)]), now);

        // Carrier loss drains with no timer involved.
        let actions = planner.evaluate(&carrier(&[("es0", false)]), now);
        assert_eq!(actions, vec![LinkDrainAction::Drain(esi(1))]);

        // Carrier return arms the hold-off instead of undraining.
        let armed_at = now + Duration::from_secs(5);
        let actions = planner.evaluate(&carrier(&[("es0", true)]), armed_at);
        assert!(actions.is_empty(), "no undrain before the delay");
        assert_eq!(
            planner.next_deadline(),
            Some(armed_at + Duration::from_secs(30))
        );

        // Not due yet → nothing fires.
        assert!(
            planner
                .fire_due(armed_at + Duration::from_secs(29))
                .is_empty()
        );
        // Due → the Link reason releases.
        assert_eq!(
            planner.fire_due(armed_at + Duration::from_secs(30)),
            vec![LinkDrainAction::Undrain(esi(1))]
        );
        assert!(planner.next_deadline().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn holdoff_rearms_on_every_up_edge() {
        let now = Instant::now();
        let mut planner = EsLinkDrainPlanner::new();
        let _ =
            planner.replace_bindings(bindings(&[(1, "es0", 30)]), &carrier(&[("es0", true)]), now);
        let _ = planner.evaluate(&carrier(&[("es0", false)]), now);

        let first_up = now + Duration::from_secs(1);
        let _ = planner.evaluate(&carrier(&[("es0", true)]), first_up);
        assert_eq!(
            planner.next_deadline(),
            Some(first_up + Duration::from_secs(30))
        );

        // Flap: down cancels, the next up re-arms from the new edge.
        let actions = planner.evaluate(
            &carrier(&[("es0", false)]),
            first_up + Duration::from_secs(10),
        );
        assert_eq!(actions, vec![LinkDrainAction::Drain(esi(1))]);
        assert!(
            planner.next_deadline().is_none(),
            "down during the hold cancels recovery"
        );

        let second_up = first_up + Duration::from_secs(20);
        let _ = planner.evaluate(&carrier(&[("es0", true)]), second_up);
        assert_eq!(
            planner.next_deadline(),
            Some(second_up + Duration::from_secs(30))
        );
        // The original deadline must not fire.
        assert!(
            planner
                .fire_due(first_up + Duration::from_secs(30))
                .is_empty()
        );
        assert_eq!(
            planner.fire_due(second_up + Duration::from_secs(30)),
            vec![LinkDrainAction::Undrain(esi(1))]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_recovery_delay_undrains_immediately() {
        let now = Instant::now();
        let mut planner = EsLinkDrainPlanner::new();
        let _ =
            planner.replace_bindings(bindings(&[(1, "es0", 0)]), &carrier(&[("es0", true)]), now);
        let _ = planner.evaluate(&carrier(&[("es0", false)]), now);

        let actions = planner.evaluate(&carrier(&[("es0", true)]), now);
        assert_eq!(actions, vec![LinkDrainAction::Undrain(esi(1))]);
        assert!(planner.next_deadline().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn binding_removal_clears_the_link_reason() {
        let now = Instant::now();
        let mut planner = EsLinkDrainPlanner::new();
        let _ = planner.replace_bindings(
            bindings(&[(1, "es0", 30)]),
            &carrier(&[("es0", false)]),
            now,
        );

        // Unbinding while drained(Link) must release the reason —
        // unbound segments have no link reason.
        let actions = planner.replace_bindings(bindings(&[]), &carrier(&[("es0", false)]), now);
        assert_eq!(actions, vec![LinkDrainAction::Undrain(esi(1))]);
        assert!(planner.next_deadline().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn binding_change_re_evaluates_against_the_new_link_immediately() {
        let now = Instant::now();
        let mut planner = EsLinkDrainPlanner::new();
        let _ = planner.replace_bindings(
            bindings(&[(1, "es0", 30)]),
            &carrier(&[("es0", false)]),
            now,
        );

        // Rebind to a healthy link: direct undrain, no hold-off.
        let actions = planner.replace_bindings(
            bindings(&[(1, "es1", 30)]),
            &carrier(&[("es0", false), ("es1", true)]),
            now,
        );
        assert_eq!(actions, vec![LinkDrainAction::Undrain(esi(1))]);
        assert!(planner.next_deadline().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn unprojected_link_waits_for_the_feed_then_fails_closed() {
        let now = Instant::now();
        let mut planner = EsLinkDrainPlanner::new();
        // The projection does not carry the bound name yet (monitor
        // replace in flight) — no action on a stale map.
        let actions = planner.replace_bindings(bindings(&[(1, "es0", 30)]), &carrier(&[]), now);
        assert!(actions.is_empty());

        // The feed's next projection carries it as down (fail-closed
        // for a name the kernel does not have) → direct drain.
        let actions = planner.evaluate(&carrier(&[("es0", false)]), now);
        assert_eq!(actions, vec![LinkDrainAction::Drain(esi(1))]);
    }

    // ── wiring tests (injected carrier watch through the real
    //     coordinator task, drain state, and segment control) ─────

    struct Rig {
        bindings_tx: watch::Sender<EsLinkBindings>,
        carrier_tx: watch::Sender<CarrierMap>,
        drain_state: EvpnEsDrainState,
        probe: crate::evpn_segment::EvpnSegmentControlProbe,
        shutdown: CancellationToken,
        task: tokio::task::JoinHandle<()>,
    }

    fn segment(id: EthernetSegmentIdentifier) -> rustbgpd_evpn::EthernetSegment {
        rustbgpd_evpn::EthernetSegment {
            esi: id,
            member_vnis: std::collections::BTreeSet::new(),
            df_preference: 32_768,
            df_algorithm: rustbgpd_evpn::DfAlgorithm::DefaultModulo,
            df_dont_preempt: false,
            redundancy_mode: rustbgpd_evpn::RedundancyMode::AllActive,
            originator_ip: "10.0.0.1".parse().unwrap(),
        }
    }

    fn rig(initial_bindings: EsLinkBindings, initial_carrier: CarrierMap) -> Rig {
        let (bindings_tx, bindings_rx) = watch::channel(initial_bindings);
        let (carrier_tx, carrier_rx) = watch::channel(initial_carrier);
        let drain_state = EvpnEsDrainState::default();
        let probe = crate::evpn_segment::EvpnSegmentControlProbe::new();
        let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            Arc::new(rustbgpd_evpn::EvpnInstanceTable::new()),
            Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
            vec![segment(esi(1))],
        )));
        let shutdown = CancellationToken::new();
        let task = spawn(
            bindings_rx,
            CarrierFeed::Injected(carrier_rx),
            EsLinkDrainDeps {
                apply_lock: Arc::new(tokio::sync::Mutex::new(())),
                coordinator,
                drain_state: drain_state.clone(),
                segment: Some(probe.control.clone()),
                originator: None,
            },
            shutdown.clone(),
        );
        Rig {
            bindings_tx,
            carrier_tx,
            drain_state,
            probe,
            shutdown,
            task,
        }
    }

    /// Let the coordinator task run without advancing the paused
    /// clock (yields never park the timer driver).
    async fn settle() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    async fn finish(rig: Rig) {
        rig.shutdown.cancel();
        let _ = rig.task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_watch_drives_drain_and_holdoff_through_the_coordinator() {
        let mut rig = rig(
            bindings(&[(1, "es0", 30)]),
            Arc::new(carrier(&[("es0", true)])),
        );
        settle().await;
        assert!(
            rig.drain_state.snapshot().is_empty(),
            "up at boot originates immediately"
        );

        // Carrier loss → drained(Link) immediately, fanned out to the
        // segment actor as the flat set.
        rig.carrier_tx
            .send_replace(Arc::new(carrier(&[("es0", false)])));
        settle().await;
        assert_eq!(
            rig.drain_state.reasons_for(esi(1)),
            [EsDrainReason::Link].into_iter().collect()
        );
        assert!(
            rig.probe.drained_rx.borrow_and_update().contains(&esi(1)),
            "segment actor received the drained flat set"
        );

        // Recovery: no undrain before the hold-off...
        rig.carrier_tx
            .send_replace(Arc::new(carrier(&[("es0", true)])));
        settle().await;
        tokio::time::advance(Duration::from_secs(29)).await;
        settle().await;
        assert!(
            rig.drain_state.snapshot().contains(&esi(1)),
            "still drained before recovery_delay_secs elapses"
        );

        // ...and release once it elapses.
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert!(rig.drain_state.snapshot().is_empty(), "hold-off released");
        assert!(!rig.probe.drained_rx.borrow_and_update().contains(&esi(1)));

        finish(rig).await;
    }

    #[tokio::test(start_paused = true)]
    async fn down_at_boot_starts_drained_with_no_holdoff() {
        let rig = rig(
            bindings(&[(1, "es0", 30)]),
            Arc::new(carrier(&[("es0", false)])),
        );
        settle().await;
        assert_eq!(
            rig.drain_state.reasons_for(esi(1)),
            [EsDrainReason::Link].into_iter().collect()
        );
        finish(rig).await;
    }

    #[tokio::test(start_paused = true)]
    async fn flap_during_holdoff_keeps_the_segment_drained() {
        let rig = rig(
            bindings(&[(1, "es0", 5)]),
            Arc::new(carrier(&[("es0", false)])),
        );
        settle().await;
        assert!(rig.drain_state.snapshot().contains(&esi(1)));

        // Up... but it flaps down again inside the hold-off window.
        rig.carrier_tx
            .send_replace(Arc::new(carrier(&[("es0", true)])));
        settle().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        settle().await;
        rig.carrier_tx
            .send_replace(Arc::new(carrier(&[("es0", false)])));
        settle().await;
        // The original deadline passing must not undrain.
        tokio::time::advance(Duration::from_secs(3)).await;
        settle().await;
        assert!(
            rig.drain_state.snapshot().contains(&esi(1)),
            "cancelled recovery must not fire"
        );

        // Holds carrier for the full window this time → undrains.
        rig.carrier_tx
            .send_replace(Arc::new(carrier(&[("es0", true)])));
        settle().await;
        tokio::time::advance(Duration::from_secs(6)).await;
        settle().await;
        assert!(rig.drain_state.snapshot().is_empty());

        finish(rig).await;
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_binding_changes_re_evaluate_immediately() {
        let rig = rig(bindings(&[]), Arc::new(carrier(&[("es0", false)])));
        settle().await;
        assert!(
            rig.drain_state.snapshot().is_empty(),
            "no binding, no drain"
        );

        // Reload adds a binding to a live ES whose link is down →
        // drained immediately, no hold-off.
        rig.bindings_tx.send_replace(bindings(&[(1, "es0", 30)]));
        settle().await;
        assert_eq!(
            rig.drain_state.reasons_for(esi(1)),
            [EsDrainReason::Link].into_iter().collect()
        );

        // Reload removes the binding while the link is still down →
        // the Link reason clears (unbound segments hold none).
        rig.bindings_tx.send_replace(bindings(&[]));
        settle().await;
        assert!(rig.drain_state.snapshot().is_empty());

        finish(rig).await;
    }

    /// Startup seam against the REAL segment actor (ADR-0085
    /// decisions 3 + 5): the segment actor publishes its first
    /// bias/AC-gate snapshots without waiting for the carrier
    /// monitor's first probe, so a bound single-active ES whose AC is
    /// down at boot is transiently bias-eligible and ungated. Pin the
    /// convergence contract: once the link coordinator's first probe
    /// lands, the system settles on drained(Link), bias-ineligible,
    /// and an AC gate row of `Blocked` — with no further stimulus.
    #[tokio::test]
    async fn down_at_boot_converges_segment_bias_and_gate_to_drained() {
        use rustbgpd_rib::RibUpdate;
        use rustbgpd_telemetry::BgpMetrics;

        use crate::test_support::{evpn_instance, vni};

        let id = esi(1);
        let mut table = rustbgpd_evpn::EvpnInstanceTable::new();
        table
            .insert(evpn_instance(65000, 100, 100, None, false))
            .unwrap();
        let instances = Arc::new(table);
        let mut bound_segment = segment(id);
        bound_segment.member_vnis = std::collections::BTreeSet::from([vni(100)]);
        bound_segment.redundancy_mode = rustbgpd_evpn::RedundancyMode::SingleActive;
        let segments = vec![bound_segment];

        // Fake RIB: ack injects/withdraws, empty query, broadcast sub.
        let (rib_tx, mut rib_rx) = tokio::sync::mpsc::channel::<RibUpdate>(64);
        let _rib = tokio::spawn(async move {
            let (events_tx, _keepalive) = tokio::sync::broadcast::channel(16);
            while let Some(update) = rib_rx.recv().await {
                match update {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    RibUpdate::InjectEvpn { reply, .. } | RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });

        let (bindings_tx, _bindings_keepalive) = watch::channel(bindings(&[(1, "es0", 30)]));
        let (carrier_tx, carrier_rx) = watch::channel::<CarrierMap>(Arc::new(carrier(&[(
            "es0", false, // AC dead at boot
        )])));
        let (bum_tx, bum_rx) = watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
        let (bias_tx, bias_rx) = watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));

        let segment_handle = crate::evpn_segment::spawn_with_local_bias(
            &instances,
            segments.clone(),
            rib_tx,
            Some(bum_tx),
            Some(bias_tx),
            Some(bindings_tx.subscribe()),
            BgpMetrics::new(),
            CancellationToken::new(),
        )
        .expect("segment actor spawns for non-empty ES config");

        let drain_state = EvpnEsDrainState::default();
        let shutdown = CancellationToken::new();
        let task = spawn(
            bindings_tx.subscribe(),
            CarrierFeed::Injected(carrier_rx),
            EsLinkDrainDeps {
                apply_lock: Arc::new(tokio::sync::Mutex::new(())),
                coordinator: Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
                    instances.clone(),
                    Arc::new(rustbgpd_evpn::ip_vrf::IpVrfTable::new()),
                    segments,
                ))),
                drain_state: drain_state.clone(),
                segment: Some(segment_handle.runtime_control()),
                originator: None,
            },
            shutdown.clone(),
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let drained_link =
                drain_state.reasons_for(id) == [EsDrainReason::Link].into_iter().collect();
            let bias_lifted = !bias_rx.borrow().is_eligible(id, vni(100));
            let gate_blocked = bum_rx.borrow().ac_gate(id).map(|entry| entry.state)
                == Some(rustbgpd_evpn::AcGateState::Blocked);
            if drained_link && bias_lifted && gate_blocked {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "down-at-boot did not converge: drained_link={drained_link} \
                 bias_lifted={bias_lifted} gate_blocked={gate_blocked}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        drop(carrier_tx);
        shutdown.cancel();
        let _ = task.await;
        segment_handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn operator_drain_survives_link_recovery_through_the_coordinator() {
        let rig = rig(
            bindings(&[(1, "es0", 0)]),
            Arc::new(carrier(&[("es0", false)])),
        );
        settle().await;

        // Operator drains on top of the link drain.
        let _ = rig
            .drain_state
            .set_reason(esi(1), EsDrainReason::Operator, true);

        // Link recovers (zero delay → immediate release of the Link
        // reason) — the operator reason must keep the ES drained.
        rig.carrier_tx
            .send_replace(Arc::new(carrier(&[("es0", true)])));
        settle().await;
        assert_eq!(
            rig.drain_state.reasons_for(esi(1)),
            [EsDrainReason::Operator].into_iter().collect()
        );
        assert!(rig.drain_state.snapshot().contains(&esi(1)));

        finish(rig).await;
    }
}
