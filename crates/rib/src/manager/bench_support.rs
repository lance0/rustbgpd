//! Bench-only manager hot-path drivers.
//!
//! Exposed solely to workspace microbenchmarks behind the `bench-internals`
//! feature (set via `required-features` on each bench target). The `pub fn
//! bench_*` methods join the crate's public surface only when that feature is
//! enabled; in a normal (default-feature) build the whole module is compiled
//! out and nothing here is reachable.
//!
//! The fanout driver registers synthetic outbound peers, seeds the Loc-RIB, and
//! runs `distribute_changes` directly. The event-history driver calls the same
//! private publish helpers as the manager actor so the API crate can compare
//! the default no-op sink with its concrete EHM sink without widening the
//! normal public API or duplicating manager-side ring/broadcast work.

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::{mpsc, oneshot};

use super::RibManager;
use crate::event::{EvpnRouteEvent, RouteEvent};
use crate::route::Route;
use crate::update::{
    BestRoutesPage, DataplanePageError, ExactExportEncoder, FibInstallCandidatesPage,
    OutboundRouteUpdate, PeerExportPolicyReplacement, RibUpdate, RoutePage, RouteQueryKey,
    RouteQueryScope,
};

// A retirement receipt runs one actor per process. Keeping its optional capture
// here adds no fields or clocks to the normal manager build.
static RETIREMENT_ACTIVE: AtomicBool = AtomicBool::new(false);
static RETIREMENT_MEASURED: AtomicBool = AtomicBool::new(false);
static RETIREMENT_COUNTS: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static RETIREMENT_EPOCH: AtomicU64 = AtomicU64::new(0);
static RETIREMENT_READINESS: [AtomicU64; 33] = [const { AtomicU64::new(0) }; 33];

/// One synchronous owner, with no route inventories or per-query history.
/// These clocks are instrumented-build evidence, never normal-build work.
pub(in crate::manager) struct RetirementReadiness {
    epoch: u64,
    entered: tokio::time::Instant,
    last_callback: tokio::time::Instant,
    max_interval: std::time::Duration,
    labels: u8,
    other_stage: bool,
    callbacks: u64,
    body_callbacks: u64,
    admitted: u64,
    serviced: u64,
    delivered: u64,
    body_replied: u64,
}

fn retirement_epoch() -> u64 {
    if RETIREMENT_ACTIVE.load(Ordering::Acquire) {
        RETIREMENT_EPOCH.load(Ordering::Relaxed)
    } else {
        0
    }
}

pub(in crate::manager) fn retirement_body_stage(stage: Option<&'static str>) -> bool {
    matches!(
        stage,
        Some(
            "peer_adj_in_retirement"
                | "peer_attribute_gc"
                | "peer_adj_out_retirement"
                | "peer_regroup_retirement"
        )
    )
}

impl RetirementReadiness {
    pub(in crate::manager) fn new(now: tokio::time::Instant) -> Self {
        Self {
            epoch: retirement_epoch(),
            entered: now,
            last_callback: now,
            max_interval: std::time::Duration::ZERO,
            labels: 0,
            other_stage: false,
            callbacks: 0,
            body_callbacks: 0,
            admitted: 0,
            serviced: 0,
            delivered: 0,
            body_replied: 0,
        }
    }

    pub(in crate::manager) fn entered(&self) -> tokio::time::Instant {
        self.entered
    }

    pub(in crate::manager) fn checkpoint(
        &mut self,
        now: tokio::time::Instant,
        stage: Option<&'static str>,
        force: bool,
    ) {
        if self.epoch == 0 && retirement_epoch() == 0 {
            return;
        }
        self.max_interval = self
            .max_interval
            .max(now.duration_since(self.last_callback));
        self.last_callback = now;
        self.callbacks += 1;
        let label = match stage {
            Some("peer_adj_in_retirement" | "peer_attribute_gc") => 1,
            Some("peer_adj_out_retirement") => 2,
            Some("peer_regroup_retirement") => 4,
            Some("terminal_cleanup") | None => 0,
            Some(_) => {
                self.other_stage = true;
                0
            }
        };
        self.labels |= label;
        if label != 0 && !force {
            self.body_callbacks += 1;
        }
    }

    pub(in crate::manager) fn reply(
        &mut self,
        in_owner: bool,
        delivered: bool,
        cleanup_body: bool,
    ) {
        if self.epoch == 0 && retirement_epoch() == 0 {
            return;
        }
        self.serviced += 1;
        if in_owner {
            self.admitted += 1;
            self.delivered += u64::from(delivered);
            self.body_replied += u64::from(delivered && cleanup_body);
        }
    }

    fn values(
        &self,
        epoch: u64,
        max_gap: std::time::Duration,
        budget: std::time::Duration,
    ) -> [u64; 11] {
        let invalid = self.epoch == 0
            || self.epoch != epoch
            || self.labels.count_ones() != 1
            || self.other_stage;
        [
            1,
            u64::from(invalid),
            self.callbacks,
            self.body_callbacks,
            self.admitted,
            self.serviced,
            self.delivered,
            self.body_replied,
            u64::try_from(self.max_interval.as_nanos()).expect("callback interval fits u64"),
            u64::try_from(max_gap.as_nanos()).expect("opportunity gap fits u64"),
            u64::try_from(budget.as_nanos()).expect("service budget fits u64"),
        ]
    }

    pub(in crate::manager) fn finish(
        &self,
        max_gap: std::time::Duration,
        budget: std::time::Duration,
    ) {
        let epoch = retirement_epoch();
        // Owners wholly outside a capture do not contaminate later receipts.
        if epoch == 0 || self.labels == 0 {
            return;
        }
        let values = self.values(epoch, max_gap, budget);
        for phase in 0..3 {
            if self.labels & (1 << phase) == 0 {
                continue;
            }
            for (field, value) in values.into_iter().enumerate() {
                let counter = &RETIREMENT_READINESS[phase * 11 + field];
                if field >= 8 {
                    counter.fetch_max(value, Ordering::Relaxed);
                } else {
                    counter.fetch_add(value, Ordering::Relaxed);
                }
            }
        }
    }
}

pub(in crate::manager) struct RetirementSample {
    keys: usize,
    groups: usize,
    started: Option<std::time::Instant>,
}

pub(in crate::manager) fn retirement_begin(
    inventory: impl FnOnce() -> (usize, usize),
) -> Option<RetirementSample> {
    if !RETIREMENT_ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let (keys, groups) = inventory();
    Some(RetirementSample {
        keys,
        groups,
        started: RETIREMENT_MEASURED
            .load(Ordering::Relaxed)
            .then(std::time::Instant::now),
    })
}

pub(in crate::manager) fn retirement_end(phase: usize, sample: Option<RetirementSample>) {
    if let Some(sample) = sample {
        let elapsed = sample.started.map(|started| started.elapsed());
        let offset = phase * 4;
        RETIREMENT_COUNTS[offset].fetch_add(1, Ordering::Relaxed);
        RETIREMENT_COUNTS[offset + 1].fetch_add(
            u64::try_from(sample.keys).expect("retirement inventory fits u64"),
            Ordering::Relaxed,
        );
        RETIREMENT_COUNTS[offset + 2].fetch_add(
            u64::try_from(sample.groups).expect("retirement groups fit u64"),
            Ordering::Relaxed,
        );
        if let Some(elapsed) = elapsed {
            bench_add_duration(&RETIREMENT_COUNTS[offset + 3], elapsed);
        }
    }
}

#[cfg(test)]
mod retirement_readiness_tests {
    use super::RetirementReadiness;
    use std::time::Duration;

    fn manager_with_queries(
        age: Duration,
    ) -> (
        super::RibManager,
        tokio::sync::mpsc::Sender<crate::RibReadinessQuery>,
    ) {
        let (_, updates) = tokio::sync::mpsc::channel(1);
        let (_, queries) = tokio::sync::mpsc::channel(1);
        let (tx, readiness) = tokio::sync::mpsc::channel(64);
        let mut manager = super::RibManager::new(
            updates,
            queries,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        )
        .with_readiness_queries(readiness);
        assert!(manager.begin_readiness_owner(age, false));
        manager
            .replacement_readiness
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .retirement
            .epoch = 7;
        (manager, tx)
    }

    fn enqueue(
        tx: &tokio::sync::mpsc::Sender<crate::RibReadinessQuery>,
    ) -> tokio::sync::oneshot::Receiver<Result<usize, crate::RibReadinessError>> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        tx.try_send(crate::RibReadinessQuery::LocRibCount {
            reply,
            enqueued: tokio::time::Instant::now().into_std(),
        })
        .unwrap();
        answer
    }

    #[tokio::test(start_paused = true)]
    async fn actual_checkpoint_service_excludes_boundary_only_replies() {
        let (manager, tx) = manager_with_queries(Duration::ZERO);
        let entry = enqueue(&tx);
        manager.replacement_checkpoint_at("peer_adj_out_retirement", true);
        assert_eq!(entry.await.unwrap(), Ok(0));
        for _ in 0..200 {
            super::super::replacement_readiness_cleanup_checkpoint(
                &manager.replacement_readiness,
                "peer_adj_out_retirement",
                crate::adj_rib_out::RetirementProgress::Progress,
            );
        }
        let terminal = enqueue(&tx);
        manager.replacement_checkpoint_at("terminal_cleanup", true);
        assert_eq!(terminal.await.unwrap(), Ok(0));
        {
            let state = manager
                .replacement_readiness
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap();
            assert_eq!(
                (
                    state.retirement.body_callbacks,
                    state.retirement.admitted,
                    state.retirement.delivered,
                    state.retirement.body_replied
                ),
                (200, 2, 2, 0)
            );
        }
        let body = enqueue(&tx);
        tokio::time::advance(Duration::from_millis(25)).await;
        super::super::replacement_readiness_cleanup_checkpoint(
            &manager.replacement_readiness,
            "peer_adj_out_retirement",
            crate::adj_rib_out::RetirementProgress::Progress,
        );
        assert_eq!(body.await.unwrap(), Ok(0));
        let state = manager
            .replacement_readiness
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap();
        assert_eq!(
            state.retirement.body_replied, 1,
            "only the real nonforced cleanup service supplies overlap"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn actual_body_service_requires_a_healthy_delivered_reply() {
        for age in [Duration::ZERO, Duration::from_secs(31)] {
            let (manager, tx) = manager_with_queries(age);
            let answer = enqueue(&tx);
            if age.is_zero() {
                drop(answer);
            } else {
                tokio::time::advance(Duration::from_millis(25)).await;
                super::super::replacement_readiness_cleanup_checkpoint(
                    &manager.replacement_readiness,
                    "peer_adj_out_retirement",
                    crate::adj_rib_out::RetirementProgress::Progress,
                );
                assert!(answer.await.unwrap().is_err());
            }
            if age.is_zero() {
                tokio::time::advance(Duration::from_millis(25)).await;
                super::super::replacement_readiness_cleanup_checkpoint(
                    &manager.replacement_readiness,
                    "peer_adj_out_retirement",
                    crate::adj_rib_out::RetirementProgress::Progress,
                );
            }
            let state = manager
                .replacement_readiness
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap();
            assert_eq!(
                (state.retirement.admitted, state.retirement.body_replied),
                (1, 0)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn actual_cleanup_helpers_reject_empty_and_tail_only_replies() {
        use crate::adj_rib_out::{ClassifiedCheckpoint, RetirementProgress};
        // Every helper keeps serving boundary queries, including empty maps and
        // final shells. None may certify productive cleanup from that service.
        let mut body_replies = Vec::new();
        for case in 0..4 {
            let (mut manager, tx) = manager_with_queries(Duration::ZERO);
            manager
                .replacement_readiness
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap()
                .budget = Duration::ZERO;
            let mut answer = None;
            let mut saw_progress = false;
            let cleanup_label = match case {
                0 => "peer_adj_in_retirement",
                1 => "peer_adj_out_retirement",
                2 => "peer_regroup_retirement",
                _ => "peer_attribute_gc",
            };
            let mut checkpoint = ClassifiedCheckpoint(|progress| {
                // Populate real work first; inject only at the subsequent empty
                // family/storage tail, never during the element callbacks.
                if progress == RetirementProgress::Progress {
                    saw_progress = true;
                } else if answer.is_none() && (saw_progress || case == 0) {
                    answer = Some(enqueue(&tx));
                }
                super::super::replacement_readiness_cleanup_checkpoint(
                    &manager.replacement_readiness,
                    cleanup_label,
                    progress,
                );
            });
            let peer = "192.0.2.1".parse().unwrap();
            let prefix =
                rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new([10, 0, 0, 0].into(), 24));
            let route = crate::test_support::make_route_with_path_id(prefix, 0);
            match case {
                0 => crate::adj_rib_in::AdjRibIn::new(peer).retire_with(&mut checkpoint),
                1 => {
                    let mut rib = crate::adj_rib_out::AdjRibOut::new(peer);
                    rib.insert(route);
                    rib.retire_with(&mut checkpoint);
                }
                2 => {
                    let mut baseline = super::super::update_groups::RegroupBaseline::default();
                    baseline.unicast.insert((prefix, 0), route);
                    baseline.retire_with(&mut checkpoint);
                }
                _ => {
                    // One real interned element followed by the sweep tail.
                    let mut attrs = crate::attr_set::AttrSet::new(vec![]);
                    manager.attr_intern.intern(&mut attrs);
                    let readiness = manager.replacement_readiness.clone();
                    // Use a separate callback so the existing mutable borrow
                    // of the intern table never aliases the manager.
                    manager
                        .attr_intern
                        .gc_with_checkpoint(&mut ClassifiedCheckpoint(|progress| {
                            if progress == RetirementProgress::Progress {
                                saw_progress = true;
                            } else if saw_progress && answer.is_none() {
                                answer = Some(enqueue(&tx));
                            }
                            super::super::replacement_readiness_cleanup_checkpoint(
                                &readiness,
                                cleanup_label,
                                progress,
                            );
                        }));
                }
            }
            assert!(answer.is_some(), "actual tail must be reached: {case}");
            assert_eq!(answer.unwrap().await.unwrap(), Ok(0));
            let state = manager
                .replacement_readiness
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap();
            body_replies.push(state.retirement.body_replied);
            assert_eq!(state.retirement.delivered, 1);
            if case != 0 {
                assert!(state.retirement.body_callbacks > 0);
            }
        }
        assert_eq!(
            body_replies,
            [0, 0, 0, 0],
            "all real empty/tail callbacks are boundaries"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn actual_nonempty_map_checkpoint_supplies_productive_reply() {
        let (manager, tx) = manager_with_queries(Duration::ZERO);
        let answer = enqueue(&tx);
        let mut map = std::collections::HashMap::from([(1_u8, 2_u8)]);
        let context = manager.replacement_readiness.clone();
        // Zero budget makes the controlled body callback eligible without any
        // wall-clock assertion or synthetic service-origin flag.
        context.as_ref().unwrap().state.lock().unwrap().budget = Duration::ZERO;
        crate::adj_rib_out::retire_hash_map(
            &mut map,
            &mut crate::adj_rib_out::ClassifiedCheckpoint(|progress| {
                super::super::replacement_readiness_cleanup_checkpoint(
                    &context,
                    "peer_adj_out_retirement",
                    progress,
                );
            }),
        );
        assert_eq!(answer.await.unwrap(), Ok(0));
        let state = context.as_ref().unwrap().state.lock().unwrap();
        assert_eq!(state.retirement.body_replied, 1);
        assert_eq!(state.retirement.body_callbacks, 2);
    }

    #[test]
    fn inactive_capture_does_not_collect_checkpoint_or_reply_counters() {
        let now = tokio::time::Instant::now();
        let mut owner = RetirementReadiness::new(now);
        assert_eq!(owner.epoch, 0);
        owner.checkpoint(
            now + Duration::from_secs(1),
            Some("peer_adj_out_retirement"),
            false,
        );
        owner.reply(true, true, true);
        assert_eq!(
            (
                owner.callbacks,
                owner.body_callbacks,
                owner.serviced,
                owner.body_replied
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(owner.last_callback, now);
        assert_eq!(
            owner.values(7, Duration::ZERO, Duration::ZERO)[1],
            1,
            "a later active epoch cannot adopt an old owner"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn callback_intervals_include_entry_body_gc_and_final_tail() {
        let now = tokio::time::Instant::now();
        let mut owner = RetirementReadiness::new(now);
        owner.epoch = 7;
        owner.checkpoint(now, None, true);
        tokio::time::advance(Duration::from_millis(10)).await;
        owner.checkpoint(
            tokio::time::Instant::now(),
            Some("peer_adj_in_retirement"),
            false,
        );
        tokio::time::advance(Duration::from_millis(20)).await;
        owner.checkpoint(
            tokio::time::Instant::now(),
            Some("peer_attribute_gc"),
            false,
        );
        owner.reply(false, true, true); // Already queued before this owner began.
        tokio::time::advance(Duration::from_millis(10)).await;
        owner.reply(true, true, true); // Query service must not reset callback spacing.
        // The last sample must include the final backing-allocation tail.
        tokio::time::advance(Duration::from_millis(21)).await;
        owner.checkpoint(tokio::time::Instant::now(), Some("terminal_cleanup"), true);
        let values = owner.values(7, Duration::from_millis(40), Duration::from_millis(25));
        assert_eq!(&values[..8], &[1, 0, 4, 2, 1, 2, 1, 1]);
        assert_eq!(&values[8..], &[31_000_000, 40_000_000, 25_000_000]);
    }

    #[test]
    fn mixed_and_cross_capture_owners_never_supply_valid_attribution() {
        let now = tokio::time::Instant::now();
        let mut owner = RetirementReadiness::new(now);
        owner.epoch = 7;
        owner.checkpoint(now, Some("peer_adj_out_retirement"), false);
        assert_eq!(owner.values(8, Duration::ZERO, Duration::ZERO)[1], 1);
        owner.checkpoint(now, Some("peer_regroup_retirement"), false);
        assert_eq!(owner.values(7, Duration::ZERO, Duration::ZERO)[1], 1);
        owner.labels = 2;
        owner.checkpoint(now, Some("other_work"), false);
        assert_eq!(owner.values(7, Duration::ZERO, Duration::ZERO)[1], 1);
    }

    #[test]
    fn a_dropped_or_unhealthy_reply_is_not_successful_owner_overlap() {
        let now = tokio::time::Instant::now();
        let mut owner = RetirementReadiness::new(now);
        owner.epoch = 7;
        owner.reply(true, false, true);
        assert_eq!((owner.admitted, owner.serviced, owner.delivered), (1, 1, 0));
    }
}

impl RibManager {
    /// Start one process-local, bench-only capture after fixture convergence.
    /// Correctness mode exposes inventories and counters without durations.
    ///
    /// # Panics
    /// Panics when a prior capture has not finished.
    pub fn bench_start_retirement_capture(measured: bool) {
        assert!(!RETIREMENT_ACTIVE.load(Ordering::Relaxed));
        for counter in &RETIREMENT_COUNTS {
            counter.store(0, Ordering::Relaxed);
        }
        for counter in &RETIREMENT_READINESS {
            counter.store(0, Ordering::Relaxed);
        }
        RETIREMENT_EPOCH.fetch_add(1, Ordering::Relaxed);
        RETIREMENT_MEASURED.store(measured, Ordering::Relaxed);
        RETIREMENT_ACTIVE.store(true, Ordering::Release);
    }

    /// Stop after an actor FIFO barrier. Each four-field phase is calls,
    /// retired keys, groups, and elapsed nanoseconds (zero when unmeasured).
    /// Phase zero covers the VPN stage map; phase one only detached Adj-RIB-In.
    /// Phases two and three cover detached private Adj-RIB-Out and retained
    /// regroup baseline retirement, including their emptied backing allocations.
    ///
    /// # Panics
    /// Panics when no capture is active.
    #[must_use]
    pub fn bench_finish_retirement_capture() -> [u64; 16] {
        assert!(RETIREMENT_ACTIVE.swap(false, Ordering::Acquire));
        std::array::from_fn(|index| RETIREMENT_COUNTS[index].load(Ordering::Relaxed))
    }

    /// Three bounded cleanup-owner aggregates: received rows including GC,
    /// private outbound rows, and regroup baseline. Each eleven-field slot holds
    /// owners, invalid owners, callbacks, productive callbacks, in-owner query
    /// admissions, serviced queries, delivered in-owner replies, successful
    /// replies at nonforced tagged cleanup callbacks, maximum callback
    /// interval, eligible-opportunity gap, and the existing service budget.
    #[must_use]
    pub fn bench_retirement_readiness() -> [u64; 33] {
        std::array::from_fn(|index| RETIREMENT_READINESS[index].load(Ordering::Relaxed))
    }
}

/// Component-only inputs; no live group ownership or route delivery is enabled.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryScanSpec {
    pub family: &'static str,
    pub keys: usize,
    pub records: usize,
    pub sparse: bool,
    pub shared: bool,
    pub shuffled: bool,
}

/// Proof-checked capture result, separate from timing collected by the caller.
#[derive(Clone, Debug, Default)]
pub struct RecoveryScanReceipt {
    pub old_keys: usize,
    pub additions: usize,
    pub shape_callbacks: usize,
    pub comparisons: usize,
    pub mismatches: usize,
    pub selected_strategy: &'static str,
    pub selection_reason: &'static str,
    pub cold_anchor_strategy: &'static str,
    pub source_slots: usize,
    pub proof_keys: usize,
    pub retained_bytes: usize,
    pub peak_bytes: usize,
    pub empty_bytes: usize,
    pub settled_bytes: usize,
    pub shared: bool,
    pub refusal: Option<&'static str>,
}

fn scan_peer(index: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(
        0xc000_0200_u32 + u32::try_from(index).expect("bounded scan owner index"),
    ))
}

fn scan_old(spec: RecoveryScanSpec) -> impl Iterator<Item = usize> {
    let additions = if spec.sparse {
        spec.records.min(spec.keys)
    } else {
        0
    };
    additions..spec.keys + additions
}

fn scan_common_key(
    spec: RecoveryScanSpec,
    n: usize,
) -> super::update_groups::admitted_recovery::Key {
    use super::update_groups::admitted_recovery::Key;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, RouteDistinguisher, VpnPrefix, VpnRouteKey};
    let v4 = if spec.keys == 1_230_000 {
        1_000_000
    } else {
        spec.keys * 4 / 5
    };
    let prefix = if n < v4 {
        rustbgpd_wire::Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::from(u32::try_from(n).unwrap()),
            32,
        ))
    } else {
        rustbgpd_wire::Prefix::V6(Ipv6Prefix::new(std::net::Ipv6Addr::from(n as u128), 128))
    };
    if spec.family == "full-uc" {
        Key::Unicast(prefix, 0)
    } else {
        Key::Vpn(
            VpnRouteKey {
                route_distinguisher: RouteDistinguisher::ZERO,
                prefix: match prefix {
                    rustbgpd_wire::Prefix::V4(prefix) => VpnPrefix::V4 {
                        addr: prefix.addr,
                        len: prefix.len,
                    },
                    rustbgpd_wire::Prefix::V6(prefix) => VpnPrefix::V6 {
                        addr: prefix.addr,
                        len: prefix.len,
                    },
                },
            },
            0,
        )
    }
}

fn scan_evpn_key(n: usize) -> rustbgpd_wire::EvpnRouteKey {
    use rustbgpd_wire::{
        EthernetTagId, EvpnIpPrefixValue, EvpnRouteKey, Ipv4Prefix, MacAddress, RouteDistinguisher,
    };
    let n = u32::try_from(n).expect("bounded scan key");
    if n.is_multiple_of(5) {
        EvpnRouteKey::IpPrefix {
            rd: RouteDistinguisher::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)),
        }
    } else {
        let octets = n.to_be_bytes();
        EvpnRouteKey::MacIp {
            rd: RouteDistinguisher::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([2, 0, octets[0], octets[1], octets[2], octets[3]]),
            ip: None,
        }
    }
}

enum ScanCommonRoute {
    Unicast(Route),
    Vpn(crate::route::VpnRibRoute),
}

fn scan_common_route(spec: RecoveryScanSpec, n: usize, at: std::time::Instant) -> ScanCommonRoute {
    use super::update_groups::admitted_recovery::Key;
    use crate::route::{ReceivedAt, RouteOrigin, VpnRibRoute};
    let attributes = crate::attr_set::AttrSet::new(vec![]);
    match scan_common_key(spec, n) {
        Key::Unicast(prefix, path_id) => ScanCommonRoute::Unicast(Route {
            prefix,
            path_id,
            next_hop: scan_peer(0),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: scan_peer(0),
            attributes,
            received_at: ReceivedAt::from_instant(at),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::LOCALHOST,
            is_stale: false,
            is_llgr_stale: false,
            validation_state: rustbgpd_wire::RpkiValidation::default(),
            aspa_state: rustbgpd_wire::AspaValidation::default(),
            received_as_path: None,
            aspa_context: crate::route::AspaContextId::default(),
        }),
        Key::Vpn(key, path_id) => ScanCommonRoute::Vpn(VpnRibRoute {
            nlri: rustbgpd_wire::VpnNlri {
                labels: vec![],
                route_distinguisher: key.route_distinguisher,
                prefix: key.prefix,
            },
            path_id,
            next_hop: scan_peer(0),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: scan_peer(0),
            attributes,
            received_at: at,
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::LOCALHOST,
            is_stale: false,
            is_llgr_stale: false,
        }),
    }
}

fn scan_evpn_route(n: usize, at: std::time::Instant) -> crate::route::EvpnRibRoute {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EvpnIpPrefixRoute, EvpnMacIp, EvpnRoute, EvpnRouteKey, MplsLabel,
    };
    let label = MplsLabel::new(100);
    let route = match scan_evpn_key(n) {
        EvpnRouteKey::MacIp {
            rd,
            ethernet_tag,
            mac,
            ip,
        } => EvpnRoute::MacIp(EvpnMacIp {
            rd,
            ethernet_tag,
            mac,
            ip,
            esi: EthernetSegmentIdentifier::ZERO,
            label1: label,
            label2: None,
        }),
        EvpnRouteKey::IpPrefix {
            rd,
            ethernet_tag,
            prefix,
        } => EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd,
            ethernet_tag,
            prefix,
            esi: EthernetSegmentIdentifier::ZERO,
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label,
        }),
        _ => unreachable!("scan fixture uses only Type2/5"),
    };
    crate::route::EvpnRibRoute {
        route,
        next_hop: scan_peer(0),
        link_local_next_hop: None,
        peer: scan_peer(0),
        attributes: crate::attr_set::AttrSet::new(vec![]),
        received_at: at,
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::LOCALHOST,
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn shuffle_scan<T>(rows: &mut [T]) {
    let mut state = 0x2b41_fe6c_b924_4b17_u64;
    for index in (1..rows.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let target = usize::try_from(state % u64::try_from(index + 1).unwrap()).unwrap();
        rows.swap(index, target);
    }
}

/// Exercise the production count/reserve/populate/seal paths with a live older
/// universe. `phase` brackets only target work: fixture setup and proof checking
/// are outside it. A counted pass is deliberately distinct from a timed pass.
///
/// # Panics
///
/// Panics for unsupported profiles, out-of-range key/record counts, or a proof
/// that differs from the authoritative fixture or fails to release its credit.
pub fn bench_recovery_capture_scan(
    spec: RecoveryScanSpec,
    counted: bool,
    mut phase: impl FnMut(&'static str, bool),
) -> RecoveryScanReceipt {
    assert!(matches!(spec.family, "full-uc" | "full-vpn" | "evpn-soak"));
    assert!((2..=480).contains(&spec.records) && (1..=1_230_000).contains(&spec.keys));
    let mut receipt = RecoveryScanReceipt::default();
    let mut callbacks = 0;
    let mut checkpoint = |force: bool| {
        if !force {
            callbacks += 1;
        }
    };
    let result = if counted {
        run_recovery_scan(spec, &mut receipt, &mut phase, &mut checkpoint)
    } else {
        run_recovery_scan(spec, &mut receipt, &mut phase, &mut |_| {})
    };
    receipt.shape_callbacks = callbacks;
    if spec.family == "evpn-soak" && counted {
        // The unchanged EVPN walker checkpoints once per OLD key and once
        // per comparison. Common slab counters come directly from the shape.
        receipt.comparisons = if result.is_ok() {
            callbacks
                .checked_sub(receipt.old_keys)
                .expect("EVPN OLD visit checkpoints")
        } else {
            callbacks.saturating_sub(receipt.old_keys)
        };
    }
    receipt.refusal = result.err();
    receipt
}

fn run_recovery_scan(
    spec: RecoveryScanSpec,
    receipt: &mut RecoveryScanReceipt,
    phase: &mut impl FnMut(&'static str, bool),
    checkpoint: &mut impl FnMut(bool),
) -> Result<(), &'static str> {
    if spec.family == "evpn-soak" {
        run_evpn_recovery_scan(spec, receipt, phase, checkpoint)
    } else {
        run_common_recovery_scan(spec, receipt, phase, checkpoint)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the component fixture keeps untimed setup, measured capture and proof settlement in one ordered path"
)]
fn run_common_recovery_scan(
    spec: RecoveryScanSpec,
    receipt: &mut RecoveryScanReceipt,
    phase: &mut impl FnMut(&'static str, bool),
    shape_checkpoint: &mut impl FnMut(bool),
) -> Result<(), &'static str> {
    use super::update_groups::admitted_recovery::{
        AdmittedRecovery, FullCaptureFallback, FullCaptureStrategy, Key,
    };
    use crate::adj_rib_out::AdjRibOut;
    let mut ledger = AdmittedRecovery::new();
    receipt.empty_bytes = ledger.bytes();
    for index in 1..spec.records - 1 {
        ledger
            .insert_empty_with_checkpoint(scan_peer(index), &mut |_| {})
            .map_err(|e| e.cause.as_str())?;
    }
    let anchor = scan_peer(0);
    let mut table = AdjRibOut::with_capacity(anchor, spec.keys);
    let at = std::time::Instant::now();
    let mut insertion = (0..spec.keys).collect::<Vec<_>>();
    if spec.shuffled {
        shuffle_scan(&mut insertion);
    }
    for n in insertion {
        match scan_common_route(spec, n, at) {
            ScanCommonRoute::Unicast(route) => table.insert(route),
            ScanCommonRoute::Vpn(route) => table.insert_vpn(route),
        }
    }
    let uc_key = |route: &crate::route::Route| Some(Key::Unicast(route.prefix, route.path_id));
    let vpn_key = |route: &crate::route::VpnRibRoute| {
        let key = route.key();
        Some(Key::Vpn(key.nlri_key, key.path_id))
    };
    // Both warm arms retain the same cold anchor policy and actual slot lineage.
    let pure_uc = spec.family == "full-uc";
    receipt.cold_anchor_strategy = if pure_uc {
        "uc-slab-shared"
    } else {
        "exact-flat"
    };
    phase("cold_anchor_capture", true);
    let cold = (|| {
        ledger.begin_capture_with_checkpoint(anchor, &mut |_| {})?;
        let cold = ledger.capture_full_old_with_checkpoint(
            anchor,
            None,
            &table,
            pure_uc,
            uc_key,
            vpn_key,
            &mut |_| {},
        )?;
        ledger.seal_capture_with_checkpoint(anchor, &mut |_| {})?;
        Ok::<_, super::update_groups::admitted_recovery::Failure>(cold)
    })();
    phase("cold_anchor_capture", false);
    let cold = cold.map_err(|e| e.cause.as_str())?;
    if pure_uc && cold.strategy != FullCaptureStrategy::Indexed {
        return Err("anchor_not_shared");
    }
    let anchor_proof = ledger.get(&anchor).expect("sealed cold anchor proof");
    assert_eq!(anchor_proof.len(), spec.keys);
    assert!((0..spec.keys).all(|n| anchor_proof.contains(&scan_common_key(spec, n).into())));
    let hint = cold.handle;
    // Reuse some old slots, append others, and leave holes without rebuilding
    // the table from a different ordering than the immutable anchor index.
    if spec.sparse {
        let replaced = spec.records.min(spec.keys);
        let remove = |table: &mut AdjRibOut, n| match scan_common_key(spec, n) {
            Key::Unicast(prefix, id) => {
                assert!(table.withdraw(&prefix, id));
            }
            Key::Vpn(key, path_id) => {
                assert!(table.remove_vpn(&crate::route::VpnRibRouteKey {
                    nlri_key: key,
                    path_id
                }));
            }
        };
        for n in 0..replaced / 2 {
            remove(&mut table, n);
        }
        for n in spec.keys..spec.keys + replaced {
            match scan_common_route(spec, n, at) {
                ScanCommonRoute::Unicast(route) => table.insert(route),
                ScanCommonRoute::Vpn(route) => table.insert_vpn(route),
            }
        }
        for n in replaced / 2..replaced {
            remove(&mut table, n);
        }
    }
    receipt.source_slots = table.unicast_slot_count();
    let peer = scan_peer(spec.records - 1);
    phase("capture", true);
    let captured = (|| {
        ledger
            .begin_capture_with_checkpoint(peer, &mut |_| {})
            .map_err(|e| e.cause.as_str())?;
        let outcome = ledger
            .capture_full_old_with_checkpoint(
                peer,
                hint,
                &table,
                pure_uc && spec.shared,
                uc_key,
                vpn_key,
                &mut |_| {},
            )
            .map_err(|error| error.cause.as_str())?;
        receipt.old_keys = outcome.keys;
        receipt.shared = outcome.strategy == FullCaptureStrategy::Indexed;
        receipt.selected_strategy = if receipt.shared {
            "uc-slab-shared"
        } else {
            "exact-flat"
        };
        receipt.selection_reason = if !spec.shared {
            "explicit-flat-control"
        } else if !pure_uc {
            "vpn-negotiated"
        } else {
            match outcome.fallback {
                None => "eligible",
                Some(FullCaptureFallback::SharingDisabled) => "sharing-disabled",
                Some(FullCaptureFallback::MissingIndex) => "missing-index",
                Some(FullCaptureFallback::SlotChurn) => "slot-churn",
                Some(FullCaptureFallback::Representation) => "representation",
                Some(FullCaptureFallback::ShareRefused) => "share-refused",
            }
        };
        receipt.mismatches = outcome.mismatches;
        ledger
            .seal_capture_with_checkpoint(peer, &mut |_| {})
            .map_err(|e| e.cause.as_str())
    })();
    phase("capture", false);
    // Shape is measured in its own invocation, after the complete capture so
    // an unmeasured extra classification cannot prewarm its timed input.
    if captured.is_ok() {
        phase("shape", true);
        let shape = ledger
            .full_old_shape_with_checkpoint(
                hint,
                &table,
                pure_uc && spec.shared,
                uc_key,
                vpn_key,
                shape_checkpoint,
            )
            .map_err(|error| error.cause.as_str())?;
        phase("shape", false);
        receipt.additions = shape.additions;
        receipt.comparisons = shape.comparisons;
        assert_eq!(receipt.old_keys, shape.count);
    }
    receipt.retained_bytes = ledger.bytes();
    receipt.peak_bytes = ledger.peak_bytes();
    if captured.is_ok() {
        let proof = ledger.get(&peer).expect("sealed target proof");
        receipt.proof_keys = proof.len();
        assert_eq!(proof.len(), spec.keys);
        assert!(scan_old(spec).all(|n| proof.contains(&scan_common_key(spec, n).into())));
        if spec.sparse {
            assert!(!proof.contains(&scan_common_key(spec, 0).into()));
        }
    }
    for index in 0..spec.records {
        ledger.remove_with_checkpoint(&scan_peer(index), &mut |_| {});
    }
    receipt.settled_bytes = ledger.bytes();
    assert_eq!(receipt.settled_bytes, receipt.empty_bytes);
    captured
}

#[expect(
    clippy::too_many_lines,
    reason = "the component fixture keeps untimed setup, measured capture and proof settlement in one ordered path"
)]
fn run_evpn_recovery_scan(
    spec: RecoveryScanSpec,
    receipt: &mut RecoveryScanReceipt,
    phase: &mut impl FnMut(&'static str, bool),
    shape_checkpoint: &mut impl FnMut(bool),
) -> Result<(), &'static str> {
    use super::update_groups::recovery_provenance::{EvpnRecoveryProvenance, PeerSession};
    let mut ledger = EvpnRecoveryProvenance::new();
    receipt.cold_anchor_strategy = "not-measured";
    receipt.selected_strategy = if spec.shared {
        "evpn-sort-shared"
    } else {
        "exact-flat"
    };
    receipt.selection_reason = if spec.shared {
        "eligible"
    } else {
        "explicit-flat-control"
    };
    receipt.empty_bytes = ledger.daemon_usage().retained;
    let owner = |index| PeerSession {
        peer: scan_peer(index),
        session_id: 1,
    };
    for index in 0..spec.records {
        ledger
            .register(owner(index))
            .map_err(|e| e.cause.as_str())?;
    }
    let anchor = ledger.primary_handle(owner(0)).unwrap();
    ledger
        .finish_recovery(anchor)
        .map_err(|e| e.cause.as_str())?;
    ledger.begin_capture(anchor).map_err(|e| e.cause.as_str())?;
    let hint = ledger
        .share_capture(
            anchor,
            None,
            spec.keys,
            (0..spec.keys).map(scan_evpn_key),
            (spec.keys, 0),
            &mut |_| {},
        )
        .map_err(|e| e.cause.as_str())?
        .ok_or("anchor_not_shared")?;
    for n in 0..spec.keys {
        ledger
            .capture_key_with_checkpoint(anchor, scan_evpn_key(n), &mut |_| {})
            .map_err(|e| e.cause.as_str())?;
    }
    assert!(
        ledger
            .seal_capture_with_checkpoint(anchor, &mut |_| {})
            .map_err(|e| e.cause.as_str())?
    );
    let anchor_proof = ledger
        .proof(anchor)
        .unwrap()
        .expect("sealed EVPN anchor proof");
    assert_eq!(anchor_proof.len(), spec.keys);
    assert!((0..spec.keys).all(|n| anchor_proof.contains(&scan_evpn_key(n))));
    let target = ledger.primary_handle(owner(spec.records - 1)).unwrap();
    let at = std::time::Instant::now();
    let mut old = scan_old(spec)
        .map(|n| scan_evpn_route(n, at))
        .collect::<Vec<_>>();
    old.sort_unstable_by_key(crate::route::EvpnRibRoute::key);
    if spec.shuffled {
        shuffle_scan(&mut old);
    }
    phase("capture", true);
    let captured = (|| {
        ledger
            .finish_recovery(target)
            .map_err(|e| e.cause.as_str())?;
        ledger.begin_capture(target).map_err(|e| e.cause.as_str())?;
        if spec.shared {
            let count = old
                .iter()
                .inspect(|route| {
                    std::hint::black_box(route.key());
                })
                .count();
            receipt.shared = ledger
                .with_ordered_capture(
                    target,
                    count,
                    old.iter(),
                    &mut |_| {},
                    |ledger, ordered, checkpoint| {
                        phase("shape", true);
                        let shape = ledger.capture_shape(
                            Some(hint),
                            ordered.iter().map(|route| route.key()),
                            shape_checkpoint,
                        );
                        phase("shape", false);
                        let shape = shape?;
                        (receipt.old_keys, receipt.additions) = shape;
                        let shared = ledger.share_capture(
                            target,
                            Some(hint),
                            spec.keys,
                            (0..spec.keys).map(scan_evpn_key),
                            shape,
                            checkpoint,
                        )?;
                        if shared.is_some() {
                            assert!(ledger.capture_batch_with_checkpoint(
                                target,
                                ordered.iter().map(|route| route.key()),
                                checkpoint
                            )?);
                        }
                        Ok(shared)
                    },
                )
                .map_err(|error| error.cause.as_str())?
                .is_some();
            if !receipt.shared {
                return Err("capture_unavailable");
            }
        } else {
            phase("shape", true);
            let shape = ledger.capture_shape(
                None,
                old.iter().map(crate::route::EvpnRibRoute::key),
                shape_checkpoint,
            );
            phase("shape", false);
            let shape = shape.map_err(|error| error.cause.as_str())?;
            (receipt.old_keys, receipt.additions) = shape;
            ledger
                .reserve_capture(target, shape.0, &mut |_| {})
                .map_err(|error| error.cause.as_str())?;
            for route in &old {
                assert!(
                    ledger
                        .capture_key_with_checkpoint(target, route.key(), &mut |_| {})
                        .map_err(|error| error.cause.as_str())?
                );
            }
        }
        assert!(
            ledger
                .seal_capture_with_checkpoint(target, &mut |_| {})
                .map_err(|e| e.cause.as_str())?
        );
        Ok(())
    })();
    phase("capture", false);
    receipt.retained_bytes = ledger.daemon_usage().retained;
    receipt.peak_bytes = ledger.daemon_usage().peak;
    if captured.is_ok() {
        let proof = ledger.proof(target).unwrap().expect("sealed target proof");
        receipt.proof_keys = proof.len();
        assert_eq!(proof.len(), spec.keys);
        assert!(old.iter().all(|route| proof.contains(&route.key())));
        if spec.sparse {
            assert!(!proof.contains(&scan_evpn_key(0)));
        }
    }
    for index in 0..spec.records {
        if let Some(handle) = ledger.primary_handle(owner(index)) {
            assert!(ledger.retire(handle));
        }
    }
    receipt.settled_bytes = ledger.daemon_usage().retained;
    assert_eq!(receipt.settled_bytes, receipt.empty_bytes);
    captured
}

/// Structural receipt for the production prefix-to-announcing-peers index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnicastPrefixPeersMemoryReceipt {
    pub entries: usize,
    pub capacity: usize,
    pub announcers_per_prefix: usize,
    pub prefix_size: usize,
    pub peer_address_size: usize,
    pub primary_value_size: usize,
    pub epoch_size: usize,
    pub spill_slots: usize,
}

/// Compact eager/lazy ordered-index receipt for dataplane paging benchmarks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataplanePrefixIndexBenchReceipt {
    pub prefixes: usize,
    pub index_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SelectionDeferralFamilyInventoryBenchReceipt {
    routes: usize,
    checksum: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SelectionDeferralInventoryBenchReceipt {
    loc_ipv4: SelectionDeferralFamilyInventoryBenchReceipt,
    loc_ipv6: SelectionDeferralFamilyInventoryBenchReceipt,
    adj_ipv4: SelectionDeferralFamilyInventoryBenchReceipt,
    adj_ipv6: SelectionDeferralFamilyInventoryBenchReceipt,
    source_stores: usize,
    nonempty_source_stores: usize,
    min_routes_per_source: usize,
    max_routes_per_source: usize,
}

static POLICY_TRANSITION_RECEIPT_PRINTED: AtomicBool = AtomicBool::new(false);
static PCB_ENUMERATION_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_ENUMERATED_PREFIXES: AtomicUsize = AtomicUsize::new(0);
static PCB_STAGING_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_STAGING_PREFIXES: AtomicUsize = AtomicUsize::new(0);
static PCB_EXACT_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_COMMIT_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_ENQUEUE_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_TOTAL_ENUMERATION_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_STAGING_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_EXACT_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_COMMIT_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_ENQUEUE_NANOS: AtomicU64 = AtomicU64::new(0);

/// Bench-only receipt for the production EVPN dataplane generation gate.
#[derive(Debug)]
pub struct EvpnDataplaneQueryBenchReceipt {
    pub routes: Option<Vec<crate::route::EvpnRibRoute>>,
    pub row_visits: usize,
}

/// The pre-LAN-1055 whole-table clone paid by every supervisor pass.
#[must_use]
pub fn bench_evpn_dataplane_legacy_snapshot(
    rows: &[crate::route::EvpnRibRoute],
) -> Vec<crate::route::EvpnRibRoute> {
    rows.to_vec()
}

/// Time the production collection helper without receipt instrumentation.
#[must_use]
pub fn bench_evpn_dataplane_generation_query(
    rows: &[crate::route::EvpnRibRoute],
    relevant_rows: usize,
    known_generation: Option<u64>,
    current_generation: u64,
) -> Option<Vec<crate::route::EvpnRibRoute>> {
    super::collect_evpn_dataplane_routes(
        rows.iter(),
        known_generation,
        current_generation,
        rows.len(),
        relevant_rows,
    )
}

/// Drive the same generation equality and Type 1/2/3/5 materialization helper
/// used by the production actor query, with a deterministic visit receipt.
#[must_use]
pub fn bench_evpn_dataplane_generation_snapshot(
    rows: &[crate::route::EvpnRibRoute],
    known_generation: Option<u64>,
    current_generation: u64,
) -> EvpnDataplaneQueryBenchReceipt {
    let relevant_rows = rows
        .iter()
        .filter(|route| rustbgpd_wire::is_dataplane_route_type(route.route_type()))
        .count();
    let visits = Cell::new(0usize);
    let routes = super::collect_evpn_dataplane_routes(
        rows.iter()
            .inspect(|_| visits.set(visits.get().saturating_add(1))),
        known_generation,
        current_generation,
        rows.len(),
        relevant_rows,
    );
    EvpnDataplaneQueryBenchReceipt {
        routes,
        row_visits: visits.get(),
    }
}

#[derive(Clone, Copy)]
struct PerClientBestCandidateBenchAggregate {
    capture_active: bool,
    prefix_visits: usize,
    empty_sets: usize,
    singleton_sets: usize,
    multi_sets: usize,
    heap_backed_collections: usize,
}

impl PerClientBestCandidateBenchAggregate {
    const INACTIVE: Self = Self {
        capture_active: false,
        prefix_visits: 0,
        empty_sets: 0,
        singleton_sets: 0,
        multi_sets: 0,
        heap_backed_collections: 0,
    };

    const fn active() -> Self {
        Self {
            capture_active: true,
            ..Self::INACTIVE
        }
    }
}

thread_local! {
    static PCB_CANDIDATE_AGGREGATE: Cell<PerClientBestCandidateBenchAggregate> =
        const { Cell::new(PerClientBestCandidateBenchAggregate::INACTIVE) };
}

/// Bench-only proof that an authoritative per-client-best policy replacement
/// traversed the real full-resync selection arm. Durations are deliberately
/// coarse per-peer totals; no clock is read inside the prefix loop.
#[derive(Clone, Copy, Debug)]
pub struct PerClientBestResyncBenchReceipt {
    pub candidate_prefix_visits: usize,
    pub empty_candidate_sets: usize,
    pub singleton_candidate_sets: usize,
    pub multi_candidate_sets: usize,
    pub heap_backed_candidate_collections: usize,
    pub enumeration_phases: usize,
    pub enumerated_prefixes: usize,
    pub staging_phases: usize,
    pub staging_prefixes: usize,
    pub exact_phases: usize,
    pub commit_phases: usize,
    pub enqueue_phases: usize,
    pub total_enumeration: std::time::Duration,
    pub total_staging: std::time::Duration,
    pub total_exact_build_and_encode: std::time::Duration,
    pub total_private_commit: std::time::Duration,
    pub total_enqueue: std::time::Duration,
    pub pending_regroup_baselines: usize,
    pub pending_extra_withdraw_peers: usize,
    pub pending_exact_export_withdrawals: usize,
    pub exact_export_rejection_peers: usize,
    pub outbound_prefix_limit_peers: usize,
    pub forced_resync_peers: usize,
}

fn bench_duration_nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn bench_add_duration(total: &AtomicU64, elapsed: std::time::Duration) {
    let nanos = bench_duration_nanos(elapsed);
    let _ = total.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(nanos))
    });
}

fn selection_deferral_prefix_checksum(prefix: Prefix) -> u64 {
    let raw = match prefix {
        Prefix::V4(prefix) => {
            u64::from(u32::from(prefix.addr))
                ^ (u64::from(prefix.len) << 32)
                ^ 0x04d5_1ec7_10a7_0001
        }
        Prefix::V6(prefix) => {
            let address = u128::from(prefix.addr);
            u64::try_from(address >> 64).expect("upper IPv6 half fits u64")
                ^ u64::try_from(address & u128::from(u64::MAX)).expect("lower IPv6 half fits u64")
                ^ (u64::from(prefix.len) << 48)
                ^ 0x06d5_1ec7_10a7_0001
        }
    };
    let mut mixed = raw.wrapping_add(0x9e37_79b9_7f4a_7c15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

fn selection_deferral_add_inventory(
    receipt: &mut SelectionDeferralFamilyInventoryBenchReceipt,
    prefix: Prefix,
) {
    receipt.routes = receipt.routes.saturating_add(1);
    receipt.checksum = receipt
        .checksum
        .wrapping_add(selection_deferral_prefix_checksum(prefix));
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "Prometheus integer counters are exactly representable at benchmark scale"
)]
fn selection_deferral_counter_total(metrics: &rustbgpd_telemetry::BgpMetrics, name: &str) -> u64 {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .map_or(0, |family| {
            family
                .get_metric()
                .iter()
                .map(|metric| metric.get_counter().get_value() as u64)
                .sum()
        })
}

pub(in crate::manager) fn bench_record_per_client_best_candidates(
    cardinality: usize,
    heap_backed: bool,
) {
    PCB_CANDIDATE_AGGREGATE.with(|aggregate| {
        let mut receipt = aggregate.get();
        if !receipt.capture_active {
            return;
        }
        receipt.prefix_visits = receipt.prefix_visits.saturating_add(1);
        match cardinality {
            0 => receipt.empty_sets = receipt.empty_sets.saturating_add(1),
            1 => receipt.singleton_sets = receipt.singleton_sets.saturating_add(1),
            _ => receipt.multi_sets = receipt.multi_sets.saturating_add(1),
        }
        if heap_backed {
            receipt.heap_backed_collections = receipt.heap_backed_collections.saturating_add(1);
        }
        aggregate.set(receipt);
    });
}

pub(in crate::manager) fn bench_record_per_client_best_enumeration(
    prefixes: usize,
    elapsed: std::time::Duration,
) {
    PCB_ENUMERATION_PHASES.fetch_add(1, Ordering::Relaxed);
    PCB_ENUMERATED_PREFIXES.fetch_add(prefixes, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_ENUMERATION_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_staging(
    prefixes: usize,
    elapsed: std::time::Duration,
) {
    PCB_STAGING_PHASES.fetch_add(1, Ordering::Relaxed);
    PCB_STAGING_PREFIXES.fetch_add(prefixes, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_STAGING_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_exact(elapsed: std::time::Duration) {
    PCB_EXACT_PHASES.fetch_add(1, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_EXACT_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_commit(elapsed: std::time::Duration) {
    PCB_COMMIT_PHASES.fetch_add(1, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_COMMIT_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_enqueue(elapsed: std::time::Duration) {
    PCB_ENQUEUE_PHASES.fetch_add(1, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_ENQUEUE_NANOS, elapsed);
}

/// Instrumentation from the production clean-transition state machine.
#[derive(Clone, Copy, Debug)]
pub struct PolicyTransitionBenchReceipt {
    pub plan_builds: usize,
    pub full_exact_probes: usize,
    pub route_shell_materializations: usize,
    pub actor_polls: usize,
    pub max_actor_poll: std::time::Duration,
    pub max_prefix_snapshot_poll: std::time::Duration,
    pub max_finalize_poll: std::time::Duration,
    pub max_commit_poll: std::time::Duration,
    pub authoritative_peer_applies: usize,
    pub max_authoritative_peer_apply: std::time::Duration,
    pub max_uninterrupted_work: std::time::Duration,
}

/// Evidence that the fanout benchmark traversed the intended production
/// ingress and authoritative grouped commit paths rather than an
/// equality-suppressed or fallback path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdjRibOutFanoutBenchReceipt {
    pub update_groups: usize,
    pub grouped_peers: usize,
    pub ungrouped_peers: usize,
    pub dirty_peers: usize,
    pub grouped_unicast_routes: usize,
    pub private_unicast_routes: usize,
    pub routes_received_dispatches: usize,
    pub routes_received_withdrawals: usize,
    pub exact_probe_batches: usize,
    pub exact_probe_candidates: usize,
    pub exact_probe_nonzero_encoded_lengths: usize,
    pub exact_probe_cache_reuses: usize,
    pub successful_commits: usize,
    pub successful_enqueues: usize,
    pub family_gauge_writes: usize,
    pub last_family_gauge_write_mask: u8,
    pub pristine_otc_reconcile_candidates: usize,
    pub private_extra_prefix_scans: usize,
    pub first_peer_family_values: [i64; 7],
}

impl RibManager {
    /// Stable checksum contribution shared by the selection-deferral fixture
    /// generator and the actor-owned inventory walk.
    #[must_use]
    pub fn bench_selection_deferral_prefix_checksum(prefix: Prefix) -> u64 {
        selection_deferral_prefix_checksum(prefix)
    }

    /// Register one GR-waiting eBGP route-server session per synthetic peer.
    /// The returned receivers retain release-time payloads and `EoR`s; only any
    /// registration-time envelope is drained.
    ///
    /// # Panics
    ///
    /// Panics for an empty peer/family fixture, a peer index outside the
    /// benchmark address space, or an invalid channel capacity.
    #[must_use]
    pub fn bench_register_selection_deferral_route_server_peers<F>(
        &mut self,
        n_peers: usize,
        gate_families: &[(Afi, Safi)],
        sendable_families: &[(Afi, Safi)],
        channel_capacity: usize,
        mut make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        assert!(n_peers > 0, "selection-deferral fixture needs peers");
        assert!(
            !gate_families.is_empty(),
            "selection-deferral fixture needs gate families"
        );
        assert!(
            !sendable_families.is_empty(),
            "selection-deferral fixture needs sendable families"
        );
        let mut receivers = Vec::with_capacity(n_peers);
        for index in 0..n_peers {
            let peer = Self::bench_peer_address(index);
            let session_id = u64::try_from(index)
                .expect("bench peer index fits u64")
                .saturating_add(1);
            let peer_asn = 4_200_000_000u32
                .saturating_add(u32::try_from(index).expect("bench peer index fits u32"));
            self.handle_update(RibUpdate::SetPeerGracefulRestartContext {
                peer,
                session_id,
                peer_restart_state: false,
                peer_gr_families: gate_families.to_vec(),
                peer_enhanced_refresh: true,
                peer_llgr_families: Vec::new(),
                local_llgr_stale_time: 0,
            });
            let (outbound_tx, mut outbound_rx) = mpsc::channel(channel_capacity);
            self.pending_peer_export_encoders
                .insert((peer, session_id), make_exact_export_encoder(peer_asn));
            self.handle_peer_up(
                peer,
                session_id,
                peer_asn,
                Ipv4Addr::new(192, 0, 2, 1),
                outbound_tx,
                None,
                sendable_families.to_vec(),
                true,
                false,
                None,
                false,
                false,
                Vec::new(),
                0,
                Vec::new(),
                Vec::new(),
            );
            while outbound_rx.try_recv().is_ok() {}
            receivers.push(outbound_rx);
        }
        receivers
    }

    /// Return exact commutative checksums and source-store occupancy without
    /// cloning any route shell. The stable array layout is documented by the
    /// sole bench target that consumes this feature-gated seam.
    ///
    /// # Panics
    ///
    /// Panics only on a platform whose `usize` route count exceeds `u64`.
    #[must_use]
    pub fn bench_selection_deferral_inventory(&self) -> [u64; 12] {
        let mut receipt = SelectionDeferralInventoryBenchReceipt {
            source_stores: self.ribs.len(),
            min_routes_per_source: usize::MAX,
            ..SelectionDeferralInventoryBenchReceipt::default()
        };
        for route in self.loc_rib.iter() {
            match route.prefix {
                Prefix::V4(_) => {
                    selection_deferral_add_inventory(&mut receipt.loc_ipv4, route.prefix);
                }
                Prefix::V6(_) => {
                    selection_deferral_add_inventory(&mut receipt.loc_ipv6, route.prefix);
                }
            }
        }
        for rib in self.ribs.values() {
            let rows = rib.len();
            if rows > 0 {
                receipt.nonempty_source_stores = receipt.nonempty_source_stores.saturating_add(1);
            }
            receipt.min_routes_per_source = receipt.min_routes_per_source.min(rows);
            receipt.max_routes_per_source = receipt.max_routes_per_source.max(rows);
            for route in rib.iter() {
                match route.prefix {
                    Prefix::V4(_) => {
                        selection_deferral_add_inventory(&mut receipt.adj_ipv4, route.prefix);
                    }
                    Prefix::V6(_) => {
                        selection_deferral_add_inventory(&mut receipt.adj_ipv6, route.prefix);
                    }
                }
            }
        }
        if self.ribs.is_empty() {
            receipt.min_routes_per_source = 0;
        }
        [
            u64::try_from(receipt.loc_ipv4.routes).expect("route count fits u64"),
            receipt.loc_ipv4.checksum,
            u64::try_from(receipt.loc_ipv6.routes).expect("route count fits u64"),
            receipt.loc_ipv6.checksum,
            u64::try_from(receipt.adj_ipv4.routes).expect("route count fits u64"),
            receipt.adj_ipv4.checksum,
            u64::try_from(receipt.adj_ipv6.routes).expect("route count fits u64"),
            receipt.adj_ipv6.checksum,
            u64::try_from(receipt.source_stores).expect("source-store count fits u64"),
            u64::try_from(receipt.nonempty_source_stores).expect("source-store count fits u64"),
            u64::try_from(receipt.min_routes_per_source).expect("source rows fit u64"),
            u64::try_from(receipt.max_routes_per_source).expect("source rows fit u64"),
        ]
    }

    fn bench_selection_deferral_ledger_cleared(&self) -> bool {
        // `DeferredSelectionKeys` deliberately exposes no production
        // introspection. Its derived Debug is exhaustive over every retained
        // set/map/byte counter; compare that state to a fresh ledger while
        // ignoring the fixture-local limit value.
        fn without_limits(debug: &str) -> &str {
            debug
                .split_once(", limits:")
                .map_or(debug, |(state, _)| state)
        }
        let actual = format!("{:?}", self.deferred_selection_keys);
        let empty = format!(
            "{:?}",
            super::selection_deferral::DeferredSelectionKeys::default()
        );
        without_limits(&actual) == without_limits(&empty)
    }

    /// Queue one Loc-RIB-count sentinel, time the exact production expiry
    /// call, then serve the sentinel through the production general-query drain.
    /// `expire = false` is the same-setup control.
    ///
    /// # Panics
    ///
    /// Panics unless primary updates and general queries are empty before the
    /// sentinel is queued, its depth becomes exactly one, the query replies
    /// synchronously, or the release leaves inconsistent gate/counter state.
    #[must_use]
    pub fn bench_selection_deferral_release_with_sentinel(
        &mut self,
        query_tx: &mpsc::Sender<RibUpdate>,
        families: &[(Afi, Safi)],
        snapshot_peer: IpAddr,
        expire: bool,
    ) -> [u64; 14] {
        let primary_depth_before = self.primary_backlog();
        assert_eq!(primary_depth_before, 0, "primary update lane must be empty");
        assert_eq!(
            self.query_rx.len(),
            0,
            "general query lane must start empty"
        );

        let releases_before = selection_deferral_counter_total(
            &self.metrics,
            "bgp_selection_deferral_releases_total",
        );
        let timeouts_before = selection_deferral_counter_total(
            &self.metrics,
            "bgp_selection_deferral_timeouts_total",
        );
        let overflows_before = selection_deferral_counter_total(
            &self.metrics,
            "bgp_selection_deferral_ledger_overflows_total",
        );
        let (reply, mut response) = oneshot::channel();
        let sentinel_started = std::time::Instant::now();
        query_tx
            .try_send(RibUpdate::QueryLocRibCount { reply })
            .expect("general query channel has one reserved sentinel slot");
        let query_depth_before = self.query_rx.len();
        assert_eq!(
            query_depth_before, 1,
            "exactly one sentinel query must be queued"
        );
        let release_duration = if expire {
            let release_started = std::time::Instant::now();
            self.expire_selection_deferral();
            release_started.elapsed()
        } else {
            std::time::Duration::ZERO
        };
        self.drain_queries(1);
        let sentinel_latency = sentinel_started.elapsed();
        let sentinel_loc_rib_count = response
            .try_recv()
            .expect("Loc-RIB-count sentinel replies through the query drain");
        let query_depth_after = self.query_rx.len();

        let rows = self
            .selection_deferral
            .as_ref()
            .map_or_else(Vec::new, |selection| selection.peer_snapshot(snapshot_peer));
        let relevant = rows
            .iter()
            .filter(|row| families.contains(&(row.afi, row.safi)))
            .collect::<Vec<_>>();
        let active_gates_after = relevant.iter().filter(|row| row.active).count();
        let released_gates_after = relevant.iter().filter(|row| !row.active).count();
        let timer_released_gates_after = relevant
            .iter()
            .filter(|row| !row.active && row.release_reason == "timer")
            .count();
        let releases_after = selection_deferral_counter_total(
            &self.metrics,
            "bgp_selection_deferral_releases_total",
        );
        let timeouts_after = selection_deferral_counter_total(
            &self.metrics,
            "bgp_selection_deferral_timeouts_total",
        );

        [
            u64::try_from(release_duration.as_nanos()).unwrap_or(u64::MAX),
            u64::try_from(sentinel_latency.as_nanos()).unwrap_or(u64::MAX),
            u64::try_from(sentinel_loc_rib_count).expect("Loc-RIB count fits u64"),
            u64::try_from(primary_depth_before).expect("channel depth fits u64"),
            u64::try_from(query_depth_before).expect("channel depth fits u64"),
            u64::try_from(query_depth_after).expect("channel depth fits u64"),
            releases_after.saturating_sub(releases_before),
            timeouts_after.saturating_sub(timeouts_before),
            u64::try_from(active_gates_after).expect("gate count fits u64"),
            u64::try_from(released_gates_after).expect("gate count fits u64"),
            u64::try_from(timer_released_gates_after).expect("gate count fits u64"),
            u64::from(self.bench_selection_deferral_ledger_cleared()),
            u64::try_from(relevant.len()).expect("gate count fits u64"),
            overflows_before,
        ]
    }

    /// Populate the manager's actual production prefix-to-announcing-peers
    /// index from prebuilt keys. The caller can therefore place prefix/input
    /// construction before an allocator baseline and isolate index growth.
    ///
    /// # Panics
    ///
    /// Panics unless the index starts empty or `announcers_per_prefix` is one
    /// or two; those constraints keep memory receipts structurally comparable.
    pub fn bench_populate_unicast_prefix_peers(
        &mut self,
        prefixes: &[Prefix],
        announcers_per_prefix: usize,
    ) -> UnicastPrefixPeersMemoryReceipt {
        assert!(self.unicast_prefix_peers.is_empty());
        assert!((1..=2).contains(&announcers_per_prefix));
        let peers = [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        ];
        for &prefix in prefixes {
            for &peer in &peers[..announcers_per_prefix] {
                self.register_unicast_announcer(peer, prefix);
            }
        }
        UnicastPrefixPeersMemoryReceipt {
            entries: self.unicast_prefix_peers.len(),
            capacity: self.unicast_prefix_peers.capacity(),
            announcers_per_prefix,
            prefix_size: std::mem::size_of::<Prefix>(),
            peer_address_size: std::mem::size_of::<IpAddr>(),
            primary_value_size: std::mem::size_of::<super::PrefixAnnouncers>(),
            epoch_size: std::mem::size_of::<super::AdjRibInEpoch>(),
            spill_slots: self.unicast_prefix_peers.spills.len(),
        }
    }

    /// Synthetic peer address used by [`Self::bench_register_peers`].
    ///
    /// Keeping address construction in one helper lets paging benchmarks
    /// query a real grouped member without duplicating the registration
    /// scheme.
    ///
    /// # Panics
    ///
    /// Panics when `index` exceeds `u32::MAX`, far beyond a useful benchmark.
    #[must_use]
    pub fn bench_peer_address(index: usize) -> IpAddr {
        let idx = u32::try_from(index).expect("bench peer index fits in u32");
        let [_, b1, b2, b3] = idx.to_be_bytes();
        IpAddr::V4(Ipv4Addr::new(10, b1, b2, b3))
    }

    /// Register `n_peers` synthetic iBGP outbound peers (`10.a.b.c`), each
    /// cloning `export_policy` and advertising IPv4 unicast. Returns the peer
    /// receivers; the caller MUST hold them so the bounded channels stay open —
    /// a full or closed channel drops the fanout onto the dirty-peer resync path
    /// and stops measuring the steady-state advertise cost. Each registration's
    /// initial-table dump enqueues an End-of-RIB marker (even for an empty
    /// Loc-RIB); that marker is drained here so the channels genuinely start
    /// empty for the measured pass, independent of `channel_capacity`.
    /// `make_exact_export_encoder` must return a fresh authoritative encoder
    /// for each synthetic session so the measured path includes the same exact
    /// wire-size probe and immutable session snapshot as production. The
    /// writer-side owner fence is outside this RIB fanout benchmark.
    ///
    /// # Panics
    /// If `n_peers` exceeds `u32::MAX` — far beyond any realistic bench.
    #[must_use]
    pub fn bench_register_peers<F>(
        &mut self,
        n_peers: usize,
        export_policy: Option<&PolicyChain>,
        is_rr_client: bool,
        channel_capacity: usize,
        mut make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut() -> Arc<dyn ExactExportEncoder>,
    {
        self.bench_register_peers_with_profile(
            n_peers,
            export_policy,
            channel_capacity,
            |_| 64_512,
            false,
            false,
            is_rr_client,
            |_| make_exact_export_encoder(),
        )
    }

    /// Register one synthetic iBGP route-reflector client against the current
    /// Loc-RIB without draining its initial-table envelopes.
    ///
    /// The caller constructs the bounded channel and authoritative encoder
    /// before starting its timer, then inspects the receiver after registration
    /// to prove the timed call sent the expected route inventory and `EoR`. This
    /// keeps Loc-RIB fixture construction, channel allocation, and encoder
    /// construction outside an initial-table join measurement while still
    /// driving the same `PeerUp` registration, first update-group construction,
    /// and `send_initial_table` path as production.
    ///
    /// # Panics
    ///
    /// Panics when `index` exceeds `u32::MAX`, far beyond a useful benchmark.
    pub fn bench_join_route_reflector_peer(
        &mut self,
        index: usize,
        outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
        exact_export_encoder: Arc<dyn ExactExportEncoder>,
    ) {
        let idx = u32::try_from(index).expect("bench peer index fits u32");
        let peer = Self::bench_peer_address(index);
        let session_id = u64::from(idx) + 1;
        self.pending_peer_export_encoders
            .insert((peer, session_id), exact_export_encoder);
        self.handle_peer_up(
            peer,
            session_id,
            64_512,
            Ipv4Addr::new(192, 0, 2, 1),
            outbound_tx,
            None,
            vec![(Afi::Ipv4, Safi::Unicast)],
            false,
            true,
            None,
            false,
            true,
            Vec::new(),
            0,
            Vec::new(),
            Vec::new(),
        );
    }

    /// Register RR clients the way a reconnect burst on a busy actor does:
    /// every `PeerUp` installs its inbound half and defers its outbound
    /// registration and initial table to the run loop's queue. An
    /// unregistered placeholder at the queue head makes the actor look busy
    /// to the first joiner; the queue drain discards it like any entry whose
    /// session is gone.
    pub fn bench_defer_route_reflector_peers(
        &mut self,
        joiners: Vec<(
            usize,
            mpsc::Sender<OutboundRouteUpdate>,
            Arc<dyn ExactExportEncoder>,
        )>,
    ) {
        self.initial_dump_defer_min_routes = 0;
        self.pending_initial_registrations
            .push_back(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 255)));
        for (index, outbound_tx, encoder) in joiners {
            self.bench_join_route_reflector_peer(index, outbound_tx, encoder);
        }
    }

    /// Complete every deferred registration through the run loop's
    /// production advance seam, one call per loop turn.
    pub fn bench_complete_deferred_registrations(&mut self) {
        while !self.pending_initial_registrations.is_empty() {
            self.advance_pending_initial_registration();
        }
    }

    /// Register synthetic eBGP route-server clients with the supplied remote
    /// ASNs. All other manager-side grouping inputs remain homogeneous, so the
    /// benchmark isolates exact-export snapshot compatibility at realistic IXP
    /// fanout sizes without changing the established RR fixture above.
    #[must_use]
    pub fn bench_register_route_server_peers<F>(
        &mut self,
        remote_asns: &[u32],
        export_policy: Option<&PolicyChain>,
        channel_capacity: usize,
        make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        self.bench_register_peers_with_profile(
            remote_asns.len(),
            export_policy,
            channel_capacity,
            |index| remote_asns[index],
            true,
            false,
            false,
            make_exact_export_encoder,
        )
    }

    /// Register synthetic eBGP route-server clients on the production
    /// per-client-best per-peer fallback. Since the ADR-0126 Phase 3
    /// classifier flip a unicast-only per-client-best peer GROUPS, so the
    /// fallback these fixtures promise requires a non-unicast-only session:
    /// each peer also negotiates `VPNv4` (no VPN routes exist in any fixture,
    /// so the wire stays pure IPv4-unicast). The explicit seam keeps the
    /// grouping disqualifier visible instead of adding a positional flag to
    /// callers.
    #[must_use]
    pub fn bench_register_per_client_best_route_server_peers<F>(
        &mut self,
        remote_asns: &[u32],
        export_policy: Option<&PolicyChain>,
        channel_capacity: usize,
        make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        self.bench_register_peers_with_profile(
            remote_asns.len(),
            export_policy,
            channel_capacity,
            |index| remote_asns[index],
            true,
            true,
            false,
            make_exact_export_encoder,
        )
    }

    /// Register one synthetic iBGP RR client with negotiated IPv4-unicast
    /// Add-Path send. The returned receiver retains the initial-table route
    /// envelope and `EoR` so the caller can prove the setup inventory before
    /// measuring a replacement pass.
    ///
    /// # Panics
    ///
    /// Panics if `send_max` is zero.
    #[must_use]
    pub fn bench_register_add_path_peer(
        &mut self,
        export_policy: Option<&PolicyChain>,
        send_max: u32,
        channel_capacity: usize,
        exact_export_encoder: Arc<dyn ExactExportEncoder>,
    ) -> mpsc::Receiver<OutboundRouteUpdate> {
        assert!(
            send_max > 0,
            "Add-Path benchmark requires a nonzero send_max"
        );
        let peer = Self::bench_peer_address(0);
        let session_id = 1;
        let (tx, rx) = mpsc::channel(channel_capacity);
        self.pending_peer_export_encoders
            .insert((peer, session_id), exact_export_encoder);
        self.handle_peer_up(
            peer,
            session_id,
            64_512,
            Ipv4Addr::new(192, 0, 2, 1),
            tx,
            export_policy.cloned(),
            vec![(Afi::Ipv4, Safi::Unicast)],
            false,
            true,
            None,
            false,
            true,
            vec![(Afi::Ipv4, Safi::Unicast)],
            send_max,
            Vec::new(),
            Vec::new(),
        );
        rx
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the bench seam keeps each production PeerUp grouping dimension explicit"
    )]
    fn bench_register_peers_with_profile<P, F>(
        &mut self,
        n_peers: usize,
        export_policy: Option<&PolicyChain>,
        channel_capacity: usize,
        mut peer_asn: P,
        is_ebgp: bool,
        per_client_best: bool,
        is_rr_client: bool,
        mut make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        P: FnMut(usize) -> u32,
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        let mut receivers = Vec::with_capacity(n_peers);
        for i in 0..n_peers {
            // Unique peer address `10.b1.b2.b3` from the index; the high byte is
            // dropped (n_peers far below 2^24 for any bench).
            let idx = u32::try_from(i).expect("bench peer count fits in u32");
            let peer = Self::bench_peer_address(i);
            let session_id = u64::from(idx) + 1;
            let peer_asn = peer_asn(i);
            let (tx, mut rx) = mpsc::channel(channel_capacity);
            self.pending_peer_export_encoders
                .insert((peer, session_id), make_exact_export_encoder(peer_asn));
            // ADR-0126 Decision 1: a unicast-only per-client-best session
            // classifies Groupable, so a per-client-best fixture peer must
            // negotiate a non-unicast-only family to stay on the per-peer
            // fallback these fixtures measure. No fixture seeds VPN routes,
            // so the negotiated-but-empty family never reaches an envelope,
            // a receipt counter, or a family gauge.
            let sendable_families = if per_client_best {
                vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)]
            } else {
                vec![(Afi::Ipv4, Safi::Unicast)]
            };
            self.handle_peer_up(
                peer,
                session_id,
                peer_asn,
                Ipv4Addr::new(192, 0, 2, 1), // shared bgp-id (irrelevant to fanout cost)
                tx,
                export_policy.cloned(),
                sendable_families,
                is_ebgp,
                is_rr_client,
                None, // no ORR vantage
                per_client_best,
                true,       // interpret RFC 1997 (production default)
                Vec::new(), // no Add-Path send
                0,
                Vec::new(), // no negotiated receive-side ORF
                Vec::new(), // no negotiated LLGR families
            );
            // Drain the initial-table dump's End-of-RIB marker so the channel
            // starts empty for the measured fanout pass.
            while rx.try_recv().is_ok() {}
            receivers.push(rx);
        }
        receivers
    }

    /// Drive one production `RoutesReceived` envelope to completion through
    /// the manager dispatcher, bounded route chunks, recompute, distribution,
    /// and every mutation-version fence implemented by the selected git ref.
    /// This synchronous bench seam does not include manager-channel dequeue or
    /// Tokio actor scheduling.
    fn bench_apply_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<Route>,
        withdrawn: Vec<(Prefix, u32)>,
    ) {
        // An unregistered synthetic source deliberately takes the production
        // legacy-producer compatibility branch, whose accepted session stamp
        // is zero. Outbound benchmark peers retain their registered stamps.
        let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
        self.handle_update(RibUpdate::RoutesReceived {
            peer,
            session_id,
            announced,
            withdrawn,
            flowspec_announced: Vec::new(),
            flowspec_withdrawn: Vec::new(),
            evpn_announced: Vec::new(),
            evpn_withdrawn: Vec::new(),
            validated_with: None,
        });
        while self.process_next_route_chunk() {}
    }

    /// Drain every update already queued on the primary channel in the
    /// production actor order: finish the pending route batch one chunk at a
    /// time, and admit the next queued update only when no chunk remains.
    /// This is the synchronous core of the actor's ready-update drain without
    /// its query seams or Tokio yields.
    pub fn bench_drain_primary_updates(&mut self) {
        loop {
            if self.process_next_route_chunk() {
                continue;
            }
            let Some(update) = self.try_recv_primary() else {
                return;
            };
            self.handle_update(update);
        }
    }

    /// Inventory for production-path attribute-intern churn measurements:
    /// Adj-RIB-In routes, Loc-RIB routes, interned sets, and intern capacity.
    #[must_use]
    pub fn bench_attr_intern_inventory(&self) -> [usize; 4] {
        [
            self.ribs
                .values()
                .map(crate::adj_rib_in::AdjRibIn::len)
                .sum(),
            self.loc_rib.len(),
            self.attr_intern.len(),
            self.attr_intern.capacity(),
        ]
    }

    /// Verify that a benchmark replacement reached both live unicast stores.
    ///
    /// # Panics
    ///
    /// Panics if the route is absent or either store retained old attributes.
    pub fn bench_assert_unicast_attributes(&self, expected: &Route) {
        let adj = self.ribs[&expected.peer]
            .get(&expected.prefix, expected.path_id)
            .expect("benchmark route remains in Adj-RIB-In");
        let best = self
            .loc_rib
            .get(&expected.prefix)
            .expect("benchmark route remains in Loc-RIB");
        assert_eq!(adj.attributes, expected.attributes);
        assert_eq!(best.attributes, expected.attributes);
    }

    /// Register `n_peers` eBGP route-server clients negotiating only the
    /// given unicast families, so plain and per-client-best peers both group.
    /// The initial-table output is drained; the receivers must stay alive.
    ///
    /// # Panics
    ///
    /// Panics when the peer count exceeds `u32::MAX`.
    #[must_use]
    pub fn bench_register_unicast_route_server_peers<F>(
        &mut self,
        n_peers: usize,
        families: &[(Afi, Safi)],
        per_client_best: bool,
        channel_capacity: usize,
        mut make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        (0..n_peers)
            .map(|index| {
                let idx = u32::try_from(index).expect("bench peer count fits in u32");
                let peer = Self::bench_peer_address(index);
                let session_id = u64::from(idx) + 1;
                let peer_asn = 65_100 + idx;
                let (tx, mut rx) = mpsc::channel(channel_capacity);
                self.pending_peer_export_encoders
                    .insert((peer, session_id), make_exact_export_encoder(peer_asn));
                self.handle_peer_up(
                    peer,
                    session_id,
                    peer_asn,
                    Ipv4Addr::new(192, 0, 2, 1),
                    tx,
                    None,
                    families.to_vec(),
                    true,
                    false,
                    None,
                    per_client_best,
                    true,
                    Vec::new(),
                    0,
                    Vec::new(),
                    Vec::new(),
                );
                while rx.try_recv().is_ok() {}
                rx
            })
            .collect()
    }

    /// Deliver one IPv4 unicast ROUTE-REFRESH from the peer that
    /// [`Self::bench_join_route_reflector_peer`] registered at `index`,
    /// through the production `RouteRefreshRequest` dispatch.
    ///
    /// # Panics
    ///
    /// Panics when `index` exceeds `u32::MAX`, far beyond a useful benchmark.
    pub fn bench_route_refresh_joined_peer(&mut self, index: usize) {
        let idx = u32::try_from(index).expect("bench peer index fits u32");
        self.handle_update(RibUpdate::RouteRefreshRequest {
            peer: Self::bench_peer_address(index),
            session_id: u64::from(idx) + 1,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            queued: Arc::new(AtomicBool::new(true)),
        });
    }

    /// Enter Graceful Restart for an unregistered synthetic source through the
    /// production `PeerGracefulRestart` path: its routes in `families` are
    /// retained and marked stale.
    pub fn bench_gr_restart(&mut self, peer: IpAddr, families: &[(Afi, Safi)]) {
        self.handle_update(RibUpdate::PeerGracefulRestart {
            peer,
            session_id: 0,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: families.to_vec(),
            peer_llgr_capable: false,
            peer_llgr_families: Vec::new(),
            llgr_stale_time: 0,
        });
    }

    /// Deliver one End-of-RIB through the production `EndOfRib` dispatch and
    /// return `[total_ns, unicast_recompute_ns, unicast_distribute_ns,
    /// unicast_affected, unicast_changed, retained_stale_routes,
    /// gr_complete, attr_gc_ns, stale_count_ns, stale_resolution_ns]`.
    ///
    /// # Panics
    ///
    /// Panics only if a duration or count exceeds `u64`.
    #[must_use]
    pub fn bench_end_of_rib(&mut self, peer: IpAddr, afi: Afi, safi: Safi) -> [u64; 10] {
        self.adj_rib_out_commit_stats.eor_unicast_affected = 0;
        self.adj_rib_out_commit_stats.eor_unicast_changed = 0;
        self.adj_rib_out_commit_stats.eor_unicast_recompute_ns = 0;
        self.adj_rib_out_commit_stats.eor_unicast_distribute_ns = 0;
        self.adj_rib_out_commit_stats.eor_attr_gc_ns = 0;
        self.adj_rib_out_commit_stats.eor_stale_count_ns = 0;
        self.adj_rib_out_commit_stats.eor_stale_resolution_ns = 0;
        let started = std::time::Instant::now();
        self.handle_update(RibUpdate::EndOfRib {
            peer,
            session_id: 0,
            afi,
            safi,
        });
        let total = u64::try_from(started.elapsed().as_nanos()).expect("duration fits u64");
        let stats = self.adj_rib_out_commit_stats;
        let stale = self
            .ribs
            .get(&peer)
            .map_or(0, crate::adj_rib_in::AdjRibIn::retained_stale_count);
        [
            total,
            stats.eor_unicast_recompute_ns,
            stats.eor_unicast_distribute_ns,
            u64::try_from(stats.eor_unicast_affected).expect("count fits u64"),
            u64::try_from(stats.eor_unicast_changed).expect("count fits u64"),
            stale,
            u64::from(!self.gr_peers.contains_key(&peer)),
            stats.eor_attr_gc_ns,
            stats.eor_stale_count_ns,
            stats.eor_stale_resolution_ns,
        ]
    }

    /// Seed the Loc-RIB through the production dispatcher/chunk path, grouped
    /// into one envelope per synthetic source peer. A source without an
    /// outbound registration uses the production legacy-unregistered
    /// `session_id = 0` compatibility branch.
    pub fn bench_seed_loc_rib(&mut self, routes: Vec<Route>) {
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        for route in routes {
            by_peer.entry(route.peer).or_default().push(route);
        }
        for (peer, announced) in by_peer {
            self.bench_apply_routes_received(peer, announced, Vec::new());
        }
    }

    /// Withdraw a prepared unicast inventory through one production
    /// `RoutesReceived` envelope. Callers build the owned withdrawal vector
    /// before starting their timer so the measured interval begins at the
    /// manager dispatcher and ends after its bounded route-chunk, recompute,
    /// and distribution work drains. Manager-channel dequeue and Tokio actor
    /// scheduling are outside this synchronous benchmark.
    pub fn bench_withdraw_loc_rib(&mut self, peer: IpAddr, withdrawn: Vec<(Prefix, u32)>) {
        self.bench_apply_routes_received(peer, Vec::new(), withdrawn);
    }

    /// Withdraw and re-announce an existing unicast subset through production
    /// `RoutesReceived` envelopes. The final table is identical to the input
    /// fixture, so traversal remains a checksum oracle while the timed control
    /// includes each ref's actual chunking and invalidation behavior.
    ///
    /// # Panics
    ///
    /// Panics if a requested fixture route was not present in its source
    /// Adj-RIB-In; that would make the churn control incomparable.
    pub fn bench_churn_loc_rib(&mut self, routes: Vec<Route>) {
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        for route in routes {
            by_peer.entry(route.peer).or_default().push(route);
        }
        for (&peer, peer_routes) in &by_peer {
            let withdrawn = peer_routes
                .iter()
                .map(|route| (route.prefix, route.path_id))
                .collect();
            self.bench_apply_routes_received(peer, Vec::new(), withdrawn);
        }
        for (peer, announced) in by_peer {
            self.bench_apply_routes_received(peer, announced, Vec::new());
        }
    }

    /// Fan `changed` out to every registered peer — the measured hot path. Both
    /// `distribute_changes` arguments are `changed`: for the bench's single-best,
    /// no-Add-Path peers, best-changed and affected are the same set.
    pub fn bench_distribute(&mut self, changed: &HashSet<Prefix>) {
        self.distribute_changes(changed, changed);
    }

    /// Replace existing unicast routes in their source Adj-RIB-In and
    /// recompute Loc-RIB without distributing the change. This fixture-only
    /// seam puts a real wire-visible change immediately in front of the timed
    /// production distribution path; setup, interning, and recompute remain
    /// outside the accumulated duration.
    ///
    /// # Panics
    ///
    /// Panics if a source Adj-RIB-In is absent or the replacement does not
    /// change every requested Loc-RIB best.
    #[must_use]
    pub fn bench_prepare_unicast_replacement(&mut self, routes: Vec<Route>) -> HashSet<Prefix> {
        let expected = routes.len();
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        for route in routes {
            by_peer.entry(route.peer).or_default().push(route);
        }

        let mut changed = HashSet::new();
        for (peer, mut routes) in by_peer {
            let mut affected = HashSet::with_capacity(routes.len());
            for route in &mut routes {
                self.attr_intern.intern(&mut route.attributes);
                affected.insert(route.prefix);
            }
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("benchmark source Adj-RIB-In remains registered");
            for route in routes {
                rib.insert(route);
            }
            for prefix in &affected {
                self.register_unicast_announcer(peer, *prefix);
            }
            changed.extend(self.recompute_best_after_announce(peer, &affected));
        }
        assert_eq!(
            changed.len(),
            expected,
            "every benchmark replacement must change its Loc-RIB best"
        );
        changed
    }

    /// Replace a multi-path prefix's complete candidate inventory without
    /// distributing it. Unlike the single-best replacement helper, every
    /// candidate may change while the selected best remains stable.
    ///
    /// # Panics
    ///
    /// Panics if any replacement's source `AdjRibIn` is absent.
    #[must_use]
    pub fn bench_prepare_multipath_replacement(&mut self, routes: Vec<Route>) -> HashSet<Prefix> {
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        let mut affected = HashSet::new();
        for route in routes {
            affected.insert(route.prefix);
            by_peer.entry(route.peer).or_default().push(route);
        }
        for (peer, mut routes) in by_peer {
            let mut peer_affected = HashSet::with_capacity(routes.len());
            for route in &mut routes {
                self.attr_intern.intern(&mut route.attributes);
                peer_affected.insert(route.prefix);
            }
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("benchmark source Adj-RIB-In remains registered");
            for route in routes {
                rib.insert(route);
            }
            for prefix in &peer_affected {
                self.register_unicast_announcer(peer, *prefix);
            }
            let _ = self.recompute_best_after_announce(peer, &peer_affected);
        }
        affected
    }

    /// Count the production Adj-RIB-In candidates for `prefix` through the
    /// same reverse-index collector used by Add-Path selection.
    #[must_use]
    pub fn bench_unicast_candidate_count(&self, prefix: Prefix) -> usize {
        Self::unicast_candidates(&self.ribs, &self.unicast_prefix_peers, &prefix).count()
    }

    /// Reset the production-path counters immediately before one measured
    /// fanout pass.
    pub fn bench_reset_adj_rib_out_fanout_receipt(&mut self) {
        self.adj_rib_out_commit_stats = super::AdjRibOutCommitStats::default();
    }

    /// Reset the feature-gated per-client-best full-resync instrumentation.
    pub fn bench_reset_per_client_best_resync_receipt(&mut self) {
        PCB_CANDIDATE_AGGREGATE.set(PerClientBestCandidateBenchAggregate::active());
        for counter in [
            &PCB_ENUMERATION_PHASES,
            &PCB_ENUMERATED_PREFIXES,
            &PCB_STAGING_PHASES,
            &PCB_STAGING_PREFIXES,
            &PCB_EXACT_PHASES,
            &PCB_COMMIT_PHASES,
            &PCB_ENQUEUE_PHASES,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        for total in [
            &PCB_TOTAL_ENUMERATION_NANOS,
            &PCB_TOTAL_STAGING_NANOS,
            &PCB_TOTAL_EXACT_NANOS,
            &PCB_TOTAL_COMMIT_NANOS,
            &PCB_TOTAL_ENQUEUE_NANOS,
        ] {
            total.store(0, Ordering::Relaxed);
        }
    }

    /// Capture the most recent per-client-best full-resync phase and residue
    /// proof. The returned non-`Eq` receipt deliberately carries durations.
    #[must_use]
    pub fn bench_per_client_best_resync_receipt(&self) -> PerClientBestResyncBenchReceipt {
        let candidates = PCB_CANDIDATE_AGGREGATE.get();
        PCB_CANDIDATE_AGGREGATE.set(PerClientBestCandidateBenchAggregate {
            capture_active: false,
            ..candidates
        });
        let load = |counter: &AtomicUsize| counter.load(Ordering::Relaxed);
        let duration =
            |total: &AtomicU64| std::time::Duration::from_nanos(total.load(Ordering::Relaxed));
        PerClientBestResyncBenchReceipt {
            candidate_prefix_visits: candidates.prefix_visits,
            empty_candidate_sets: candidates.empty_sets,
            singleton_candidate_sets: candidates.singleton_sets,
            multi_candidate_sets: candidates.multi_sets,
            heap_backed_candidate_collections: candidates.heap_backed_collections,
            enumeration_phases: load(&PCB_ENUMERATION_PHASES),
            enumerated_prefixes: load(&PCB_ENUMERATED_PREFIXES),
            staging_phases: load(&PCB_STAGING_PHASES),
            staging_prefixes: load(&PCB_STAGING_PREFIXES),
            exact_phases: load(&PCB_EXACT_PHASES),
            commit_phases: load(&PCB_COMMIT_PHASES),
            enqueue_phases: load(&PCB_ENQUEUE_PHASES),
            total_enumeration: duration(&PCB_TOTAL_ENUMERATION_NANOS),
            total_staging: duration(&PCB_TOTAL_STAGING_NANOS),
            total_exact_build_and_encode: duration(&PCB_TOTAL_EXACT_NANOS),
            total_private_commit: duration(&PCB_TOTAL_COMMIT_NANOS),
            total_enqueue: duration(&PCB_TOTAL_ENQUEUE_NANOS),
            pending_regroup_baselines: self.pending_regroup_baseline.len(),
            pending_extra_withdraw_peers: self.pending_extra_withdraws.len(),
            pending_exact_export_withdrawals: self.pending_exact_export_withdrawals.len(),
            exact_export_rejection_peers: self.peer_unexportable.len(),
            outbound_prefix_limit_peers: self.outbound_prefix_limits.len(),
            forced_resync_peers: self.force_outbound_peers.len(),
        }
    }

    /// Capture production-path and current metric evidence after one measured
    /// fanout pass.
    #[must_use]
    pub fn bench_adj_rib_out_fanout_receipt(&self) -> AdjRibOutFanoutBenchReceipt {
        use super::update_groups::GroupMembership;

        let group_ids = self
            .update_groups
            .members
            .values()
            .filter_map(|membership| match membership {
                GroupMembership::Grouped(group_id) => Some(*group_id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let grouped_peers = self
            .update_groups
            .members
            .values()
            .filter(|membership| matches!(membership, GroupMembership::Grouped(_)))
            .count();
        let stats = self.adj_rib_out_commit_stats;
        AdjRibOutFanoutBenchReceipt {
            update_groups: group_ids.len(),
            grouped_peers,
            ungrouped_peers: self
                .update_groups
                .members
                .len()
                .saturating_sub(grouped_peers),
            dirty_peers: self.dirty_peers.len(),
            grouped_unicast_routes: self
                .group_ribs
                .values()
                .map(|group| group.table.len())
                .sum(),
            private_unicast_routes: self
                .adj_ribs_out
                .values()
                .map(super::super::adj_rib_out::AdjRibOut::len)
                .sum(),
            routes_received_dispatches: stats.routes_received_dispatches,
            routes_received_withdrawals: stats.routes_received_withdrawals,
            exact_probe_batches: stats.exact_probe_batches,
            exact_probe_candidates: stats.exact_probe_candidates,
            exact_probe_nonzero_encoded_lengths: stats.exact_probe_nonzero_encoded_lengths,
            exact_probe_cache_reuses: stats.exact_probe_cache_reuses,
            successful_commits: stats.successful_commits,
            successful_enqueues: stats.successful_enqueues,
            family_gauge_writes: stats.family_gauge_writes,
            last_family_gauge_write_mask: stats.last_family_gauge_write_mask,
            pristine_otc_reconcile_candidates: stats.pristine_otc_reconcile_candidates,
            private_extra_prefix_scans: stats.private_extra_prefix_scans,
            first_peer_family_values: self
                .bench_adj_rib_out_family_values(Self::bench_peer_address(0)),
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "benchmark fixture gauge counts are exact small nonnegative integers"
    )]
    fn bench_adj_rib_out_family_values(&self, peer: IpAddr) -> [i64; 7] {
        const FAMILIES: [&str; 7] = ["all", "flowspec", "evpn", "bgpls", "vpn", "labeled", "rtc"];
        let peer_label = peer.to_string();
        let gathered = self.metrics.registry().gather();
        let Some(gauge) = gathered
            .iter()
            .find(|family| family.name() == "bgp_rib_adj_out_prefixes")
        else {
            return [0; 7];
        };
        std::array::from_fn(|index| {
            gauge
                .get_metric()
                .iter()
                .find(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "peer" && label.value() == peer_label)
                        && metric.get_label().iter().any(|label| {
                            label.name() == "afi_safi" && label.value() == FAMILIES[index]
                        })
                })
                .map_or(0, |metric| metric.get_gauge().get_value() as i64)
        })
    }

    /// Apply one export-policy replacement to every synthetic peer through
    /// the shared clean-transition seam. Returns whether the fast path was
    /// selected.
    ///
    /// # Panics
    ///
    /// Panics if the fast path falls back and any of the first `n_peers`
    /// synthetic peers was not registered by the benchmark fixture.
    pub fn bench_replace_export_policy_cohort(
        &mut self,
        n_peers: usize,
        export_policy: &PolicyChain,
    ) -> bool {
        self.policy_transition_stats = super::PolicyTransitionStats::default();
        let replacements = (0..n_peers)
            .map(|index| PeerExportPolicyReplacement {
                peer: Self::bench_peer_address(index),
                export_policy: Some(export_policy.clone()),
            })
            .collect::<Vec<_>>();
        let fast = self.try_clean_group_policy_transition(&replacements);
        if !fast {
            for replacement in replacements {
                self.bench_apply_authoritative_export_policy(
                    replacement.peer,
                    replacement.export_policy,
                );
            }
        }
        self.bench_maybe_print_policy_transition_receipt(n_peers, fast);
        fast
    }

    fn bench_apply_authoritative_export_policy(
        &mut self,
        peer: IpAddr,
        export_policy: Option<PolicyChain>,
    ) {
        let started = std::time::Instant::now();
        self.replace_peer_export_policy_synchronously(peer, export_policy)
            .expect("synthetic peer remains registered");
        let elapsed = started.elapsed();
        self.policy_transition_stats.authoritative_peer_applies = self
            .policy_transition_stats
            .authoritative_peer_applies
            .saturating_add(1);
        self.policy_transition_stats.max_authoritative_peer_apply = self
            .policy_transition_stats
            .max_authoritative_peer_apply
            .max(elapsed);
    }

    fn bench_maybe_print_policy_transition_receipt(&self, n_peers: usize, fast: bool) {
        if std::env::var_os("RUSTBGPD_POLICY_TRANSITION_RECEIPT").is_some()
            && !POLICY_TRANSITION_RECEIPT_PRINTED.swap(true, Ordering::Relaxed)
        {
            let receipt = self.bench_policy_transition_receipt();
            eprintln!(
                "policy_transition_receipt peers={n_peers} fast={fast} plans={} \
                 full_exact_probes={} route_shell_materializations={} actor_polls={} \
                 max_actor_poll_ns={} max_prefix_snapshot_poll_ns={} max_finalize_poll_ns={} \
                 max_commit_poll_ns={} \
                 authoritative_peer_applies={} max_authoritative_peer_apply_ns={} \
                 max_uninterrupted_work_ns={}",
                receipt.plan_builds,
                receipt.full_exact_probes,
                receipt.route_shell_materializations,
                receipt.actor_polls,
                receipt.max_actor_poll.as_nanos(),
                receipt.max_prefix_snapshot_poll.as_nanos(),
                receipt.max_finalize_poll.as_nanos(),
                receipt.max_commit_poll.as_nanos(),
                receipt.authoritative_peer_applies,
                receipt.max_authoritative_peer_apply.as_nanos(),
                receipt.max_uninterrupted_work.as_nanos(),
            );
        }
    }

    /// Authoritative old path for A/B policy-regroup measurements.
    ///
    /// # Panics
    ///
    /// Panics if any of the first `n_peers` synthetic peers was not registered
    /// by the benchmark fixture.
    pub fn bench_replace_export_policy_per_peer(
        &mut self,
        n_peers: usize,
        export_policy: &PolicyChain,
    ) {
        self.policy_transition_stats = super::PolicyTransitionStats::default();
        for index in 0..n_peers {
            self.bench_apply_authoritative_export_policy(
                Self::bench_peer_address(index),
                Some(export_policy.clone()),
            );
        }
        self.bench_maybe_print_policy_transition_receipt(n_peers, false);
    }

    /// Production state-machine instrumentation from the most recent shared
    /// transition.
    #[must_use]
    pub fn bench_policy_transition_receipt(&self) -> PolicyTransitionBenchReceipt {
        let stats = self.policy_transition_stats;
        PolicyTransitionBenchReceipt {
            plan_builds: stats.plan_builds,
            full_exact_probes: stats.full_exact_probes,
            route_shell_materializations: stats.route_shell_materializations,
            actor_polls: stats.actor_polls,
            max_actor_poll: stats.max_actor_slice,
            max_prefix_snapshot_poll: stats.max_prefix_snapshot_poll,
            max_finalize_poll: stats.max_finalize_poll,
            max_commit_poll: stats.max_commit_poll,
            authoritative_peer_applies: stats.authoritative_peer_applies,
            max_authoritative_peer_apply: stats.max_authoritative_peer_apply,
            max_uninterrupted_work: stats
                .max_actor_slice
                .max(stats.max_authoritative_peer_apply),
        }
    }

    /// Drive the production paged-query handler synchronously and return its
    /// reply. The benchmark deliberately includes the oneshot boundary while
    /// excluding async task scheduling noise.
    ///
    /// # Panics
    ///
    /// Panics if the production handler stops replying synchronously; that
    /// would invalidate this benchmark's synchronous handler-boundary model.
    #[must_use]
    pub fn bench_query_route_page(
        &mut self,
        scope: RouteQueryScope,
        after: Option<RouteQueryKey>,
        page_size: usize,
    ) -> RoutePage {
        let (reply, mut response) = oneshot::channel();
        self.handle_query_routes_page(scope, None, after, page_size, reply);
        response
            .try_recv()
            .expect("route page handler replies synchronously")
    }

    /// Return the populated ordered-prefix index's entry and allocator size.
    #[must_use]
    pub fn bench_dataplane_prefix_index_receipt(&self) -> DataplanePrefixIndexBenchReceipt {
        let (prefixes, index_bytes) = self.loc_rib.bench_ordered_index_receipt();
        DataplanePrefixIndexBenchReceipt {
            prefixes,
            index_bytes,
        }
    }

    /// Drive the internal best-route dataplane page handler synchronously.
    ///
    /// # Errors
    ///
    /// Returns the production handler's index/generation error.
    ///
    /// # Panics
    ///
    /// Panics if the production handler stops replying synchronously.
    pub fn bench_query_best_routes_page(
        &mut self,
        after: Option<Prefix>,
    ) -> Result<BestRoutesPage, DataplanePageError> {
        let (reply, mut response) = oneshot::channel();
        self.handle_query_best_routes_page(
            after,
            tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            reply,
        );
        response
            .try_recv()
            .expect("best dataplane page handler replies synchronously")
    }

    /// Drive the internal FIB-candidate dataplane page handler synchronously.
    ///
    /// # Errors
    ///
    /// Returns the production handler's index/generation error.
    ///
    /// # Panics
    ///
    /// Panics if the production handler stops replying synchronously.
    pub fn bench_query_fib_install_candidates_page(
        &mut self,
        after: Option<Prefix>,
        max_paths: u32,
    ) -> Result<FibInstallCandidatesPage, DataplanePageError> {
        let (reply, mut response) = oneshot::channel();
        self.handle_query_fib_install_candidates_page(
            after,
            max_paths,
            false,
            false,
            tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            reply,
        );
        response
            .try_recv()
            .expect("FIB dataplane page handler replies synchronously")
    }

    /// Publish an owned batch through the production route-event helper.
    ///
    /// Input construction belongs in the benchmark setup closure. Consuming
    /// the batch here keeps event cloning out of the timed manager phase while
    /// retaining the real process-local ID, ring, sink, and legacy-broadcast
    /// work performed by `RibManager::publish_route_event`.
    pub fn bench_publish_route_events(&mut self, events: impl IntoIterator<Item = RouteEvent>) {
        for event in events {
            self.publish_route_event(event);
        }
    }

    /// Publish an owned batch through the production EVPN-event helper.
    ///
    /// Like [`Self::bench_publish_route_events`], this method exists only under
    /// `bench-internals` and deliberately adds no alternate production path.
    pub fn bench_publish_evpn_events(&mut self, events: impl IntoIterator<Item = EvpnRouteEvent>) {
        for event in events {
            self.publish_evpn_route_event(event);
        }
    }
}

#[cfg(test)]
mod recovery_scan_tests {
    use super::*;
    use crate::adj_rib_out::AdjRibOut;
    use crate::manager::update_groups::admitted_recovery::{
        AdmittedRecovery, FullCaptureFallback, FullCaptureStrategy, Key,
    };

    #[test]
    fn recovery_scan_vpn_negotiation_selects_flat_with_only_unicast_rows() {
        let peer = scan_peer(1);
        let spec = RecoveryScanSpec {
            family: "full-uc",
            keys: 64,
            records: 2,
            sparse: false,
            shared: true,
            shuffled: false,
        };
        let mut table = AdjRibOut::with_capacity(peer, spec.keys);
        let at = std::time::Instant::now();
        for n in 0..spec.keys {
            let ScanCommonRoute::Unicast(route) = scan_common_route(spec, n, at) else {
                unreachable!()
            };
            table.insert(route);
        }
        let mut ledger = AdmittedRecovery::new();
        ledger
            .begin_capture_with_checkpoint(peer, &mut |_| {})
            .unwrap();
        let outcome = ledger
            .capture_full_old_with_checkpoint(
                peer,
                None,
                &table,
                false,
                |route| Some(Key::Unicast(route.prefix, route.path_id)),
                |_| None,
                &mut |_| {},
            )
            .unwrap();
        ledger
            .seal_capture_with_checkpoint(peer, &mut |_| {})
            .unwrap();
        assert_eq!(outcome.strategy, FullCaptureStrategy::Flat);
        assert_eq!(outcome.fallback, Some(FullCaptureFallback::SharingDisabled));
        assert!(outcome.handle.is_none());
        let proof = ledger.get(&peer).unwrap();
        assert_eq!(proof.len(), spec.keys);
        for n in 0..spec.keys {
            assert!(proof.contains(&scan_common_key(spec, n).into()));
        }
    }
}
