//! Event-history producer measurement gate for RIB-produced durable events.
//!
//! The `event_history_manager_self_time` group times only the synchronous
//! `RibManager::publish_*` phase. It compares the default no-op sink with the
//! real EHM sink. All no-op cases finish before EHM is started, and each EHM
//! sample starts only after the preceding sample reaches EHM's committed
//! high-water mark. Commit fences and health checks run in Criterion setup and
//! are therefore outside the timed region.
//!
//! The `event_history_sqlite_end_to_end` group starts at the same manager publish
//! helper and ends when every event is observed on EHM's post-commit broadcast.
//! It therefore includes conversion, prost encoding, the bounded queue, SQLite
//! commit, cursor allocation, and committed-event delivery.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use prometheus::Encoder;
use rustbgpd_event_history::{
    EhmState, EventHistoryConfig, EventHistoryHandle, EventHistoryManager, EventHistorySender,
    SynchronousMode,
};
use rustbgpd_rib::{
    EvpnRibRoute, EvpnRouteEvent, RibManager, RouteEvent, RouteEventType, RouteOrigin,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, AsPathSegment, EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute,
    Ipv4Prefix, MacAddress, MplsLabel, Origin, PathAttribute, Prefix, RouteDistinguisher,
};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::{broadcast, mpsc};

const EVENTS_PER_SAMPLE: usize = 256;
const EHM_QUEUE_CAPACITY: usize = 4_096;
const QUEUE_FENCE_TIMEOUT: Duration = Duration::from_secs(10);
const COMMIT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
enum EventShape {
    RouteAdded,
    RoutePolicyFiltered,
    EvpnBestChanged,
}

impl EventShape {
    const ALL: [Self; 3] = [
        Self::RouteAdded,
        Self::RoutePolicyFiltered,
        Self::EvpnBestChanged,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::RouteAdded => "route_added",
            Self::RoutePolicyFiltered => "route_policy_filtered",
            Self::EvpnBestChanged => "evpn_best_changed",
        }
    }

    fn batch(self) -> EventBatch {
        match self {
            Self::RouteAdded => EventBatch::Route(
                (0..EVENTS_PER_SAMPLE)
                    .map(|index| route_event(index, RouteEventType::Added))
                    .collect(),
            ),
            Self::RoutePolicyFiltered => EventBatch::Route(
                (0..EVENTS_PER_SAMPLE)
                    .map(|index| route_event(index, RouteEventType::PolicyFiltered))
                    .collect(),
            ),
            Self::EvpnBestChanged => EventBatch::Evpn(
                (0..EVENTS_PER_SAMPLE)
                    .map(evpn_best_changed_event)
                    .collect(),
            ),
        }
    }
}

#[derive(Clone)]
enum EventBatch {
    Route(Vec<RouteEvent>),
    Evpn(Vec<EvpnRouteEvent>),
}

impl EventBatch {
    fn publish(self, manager: &mut RibManager) {
        match self {
            Self::Route(events) => manager.bench_publish_route_events(events),
            Self::Evpn(events) => manager.bench_publish_evpn_events(events),
        }
    }
}

struct EhmHarness {
    runtime: Runtime,
    manager: Option<RibManager>,
    history: Option<EventHistoryManager>,
    handle: EventHistoryHandle,
    sender: EventHistorySender,
    metrics: BgpMetrics,
    committed_rx: Option<broadcast::Receiver<rustbgpd_event_history::CommittedEvent>>,
    last_cursor: u64,
    _dir: TempDir,
}

impl EhmHarness {
    fn new(subscribe_to_commits: bool) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("event-history-ehm")
            .enable_all()
            .build()
            .expect("event-history producer benchmark runtime");
        let dir = tempfile::tempdir().expect("event-history producer benchmark tempdir");
        let metrics = BgpMetrics::new();
        let history = runtime
            .block_on(EventHistoryManager::start(EventHistoryConfig {
                path: dir.path().join("events.db"),
                required: true,
                queue_capacity: EHM_QUEUE_CAPACITY,
                batch_size: EVENTS_PER_SAMPLE,
                batch_interval: Duration::from_millis(50),
                broadcast_capacity: EHM_QUEUE_CAPACITY,
                max_events: 10_000_000,
                max_bytes: 8_000_000_000,
                synchronous: SynchronousMode::Full,
                retention_interval: Duration::from_secs(3_600),
                sidecar_flush_interval_batches: u64::MAX,
                metrics: Some(metrics.clone()),
            }))
            .expect("start event-history producer benchmark EHM");
        let handle = history.handle();
        let sender = handle.sender();
        let committed_rx = subscribe_to_commits.then(|| handle.subscribe_live());
        let sink =
            rustbgpd_api::event_history_sinks::make_rib_event_sink(handle.clone(), metrics.clone());
        let manager = manager_with_metrics(metrics.clone()).with_event_sink(sink);

        Self {
            runtime,
            manager: Some(manager),
            history: Some(history),
            handle,
            sender,
            metrics,
            committed_rx,
            last_cursor: 0,
            _dir: dir,
        }
    }

    fn assert_healthy(&self) {
        assert_healthy(self.handle.state(), &self.metrics);
    }

    fn shutdown(mut self) {
        fence_queue(&self.sender);
        self.assert_healthy();
        assert_eq!(
            self.handle.state().latest_event_id(),
            self.last_cursor,
            "EHM committed high-water mark changed before shutdown"
        );
        drop(self.manager.take());
        let history = self.history.take().expect("EHM manager present");
        self.runtime.block_on(history.shutdown());
        self.assert_healthy();
        assert_eq!(
            self.handle.state().latest_event_id(),
            self.last_cursor,
            "EHM exposed committed high-water mark changed across shutdown"
        );
    }
}

fn manager() -> RibManager {
    manager_with_metrics(BgpMetrics::new())
}

fn manager_with_metrics(metrics: BgpMetrics) -> RibManager {
    let (_update_tx, update_rx) = mpsc::channel(16);
    let (_query_tx, query_rx) = mpsc::channel(16);
    RibManager::new(update_rx, query_rx, None, None, metrics)
}

fn route_event(index: usize, event_type: RouteEventType) -> RouteEvent {
    let [high, low] = u16::try_from(index)
        .expect("sample index fits u16")
        .to_be_bytes();
    let policy_filtered = event_type == RouteEventType::PolicyFiltered;
    RouteEvent {
        event_id: 0,
        event_type,
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 18, high, low), 32)),
        peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        previous_peer: None,
        target_peer: policy_filtered.then_some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        timestamp: "1783915200".to_string(),
        path_id: u32::try_from(index).expect("sample index fits u32"),
        reason: if policy_filtered {
            "policy_denied".to_string()
        } else {
            String::new()
        },
    }
}

fn evpn_route(peer: Ipv4Addr, index: usize) -> EvpnRibRoute {
    let [high, low] = u16::try_from(index)
        .expect("sample index fits u16")
        .to_be_bytes();
    EvpnRibRoute {
        route: EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher::new([0, 0, 0xfd, 0xe8, 0, 0, high, low]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress::new([0x02, 0, 0, 0, high, low]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, high, low))),
            label1: MplsLabel::new(10_000 + u32::try_from(index).expect("sample index fits u32")),
            label2: None,
        }),
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![64_512, 64_513])],
            }),
            PathAttribute::NextHop(peer),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn evpn_best_changed_event(index: usize) -> EvpnRouteEvent {
    let best = evpn_route(Ipv4Addr::new(192, 0, 2, 2), index);
    let previous_best = evpn_route(Ipv4Addr::new(192, 0, 2, 1), index);
    EvpnRouteEvent {
        event_type: RouteEventType::BestChanged,
        key: best.key(),
        best: Some(best),
        previous_best: Some(previous_best),
        peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
        previous_peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        timestamp: "1783915200".to_string(),
    }
}

fn fence_queue(sender: &EventHistorySender) {
    let deadline = Instant::now() + QUEUE_FENCE_TIMEOUT;
    while sender.available() != sender.max_capacity() {
        assert!(
            Instant::now() < deadline,
            "EHM producer queue did not drain within {QUEUE_FENCE_TIMEOUT:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn fence_committed_through(
    runtime: &Runtime,
    committed_rx: &mut broadcast::Receiver<rustbgpd_event_history::CommittedEvent>,
    state: &Arc<EhmState>,
    last_cursor: &mut u64,
    expected_last: u64,
) {
    assert!(
        expected_last >= *last_cursor,
        "committed high-water fence moved backwards"
    );
    runtime.block_on(async {
        tokio::time::timeout(COMMIT_TIMEOUT, async {
            while *last_cursor < expected_last {
                let expected = last_cursor.checked_add(1).expect("cursor space");
                let committed = committed_rx
                    .recv()
                    .await
                    .expect("committed-event broadcast remains open");
                assert_eq!(
                    committed.event_id, expected,
                    "EHM cursor order changed during benchmark"
                );
                *last_cursor = expected;
            }
        })
        .await
        .expect("EHM committed high-water fence timed out");
    });
    assert_eq!(
        state.latest_event_id(),
        expected_last,
        "EHM state did not reach the expected committed high-water mark"
    );
}

fn metrics_text(metrics: &BgpMetrics) -> String {
    let encoder = prometheus::TextEncoder::new();
    let families = metrics.registry().gather();
    let mut out = Vec::new();
    encoder
        .encode(&families, &mut out)
        .expect("encode benchmark metrics");
    String::from_utf8(out).expect("Prometheus text is UTF-8")
}

fn assert_healthy(state: &Arc<EhmState>, metrics: &BgpMetrics) {
    assert!(!state.degraded(), "EHM state degraded during benchmark");
    assert!(
        !metrics.event_outbox_degraded(),
        "event-outbox degraded gauge moved during benchmark"
    );
    let text = metrics_text(metrics);
    let drops: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("bgp_event_outbox_dropped_total{"))
        .collect();
    assert!(
        drops.is_empty(),
        "event-outbox drop counter moved during benchmark: {drops:?}"
    );
}

fn manager_self_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_history_manager_self_time");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.throughput(Throughput::Elements(
        u64::try_from(EVENTS_PER_SAMPLE).expect("sample size fits u64"),
    ));

    // Measure every no-op case before starting EHM so no SQLite or EHM actor
    // work can contaminate the default-disabled samples.
    let mut noop_manager = manager();
    for shape in EventShape::ALL {
        let batch = shape.batch();
        group.bench_function(format!("{}/noop", shape.label()), |bencher| {
            bencher.iter_batched(
                || batch.clone(),
                |events| events.publish(&mut noop_manager),
                BatchSize::PerIteration,
            );
        });
    }
    drop(noop_manager);

    let mut ehm = EhmHarness::new(true);
    for shape in EventShape::ALL {
        let batch = shape.batch();
        let sender = ehm.sender.clone();
        let state = ehm.handle.state().clone();
        let metrics = ehm.metrics.clone();
        let runtime = &ehm.runtime;
        let ehm_manager = ehm.manager.as_mut().expect("RIB manager present");
        let committed_rx = ehm
            .committed_rx
            .as_mut()
            .expect("manager harness subscribes before publishing");
        let last_cursor = &mut ehm.last_cursor;
        let mut expected_cursor = *last_cursor;
        group.bench_function(format!("{}/ehm", shape.label()), |bencher| {
            bencher.iter_batched(
                || {
                    fence_committed_through(
                        runtime,
                        committed_rx,
                        &state,
                        last_cursor,
                        expected_cursor,
                    );
                    fence_queue(&sender);
                    assert_healthy(&state, &metrics);
                    expected_cursor = expected_cursor
                        .checked_add(
                            u64::try_from(EVENTS_PER_SAMPLE).expect("sample size fits u64"),
                        )
                        .expect("cursor space");
                    batch.clone()
                },
                |events| events.publish(ehm_manager),
                BatchSize::PerIteration,
            );
        });
        fence_committed_through(runtime, committed_rx, &state, last_cursor, expected_cursor);
        fence_queue(&ehm.sender);
        ehm.assert_healthy();
    }

    group.finish();
    ehm.shutdown();
}

fn sqlite_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_history_sqlite_end_to_end");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.throughput(Throughput::Elements(
        u64::try_from(EVENTS_PER_SAMPLE).expect("sample size fits u64"),
    ));

    let mut ehm = EhmHarness::new(true);
    for shape in EventShape::ALL {
        let batch = shape.batch();
        let sender = ehm.sender.clone();
        let state = ehm.handle.state().clone();
        let metrics = ehm.metrics.clone();
        let runtime = &ehm.runtime;
        let ehm_manager = ehm.manager.as_mut().expect("RIB manager present");
        let committed_rx = ehm
            .committed_rx
            .as_mut()
            .expect("end-to-end harness subscribes before publishing");
        let last_cursor = &mut ehm.last_cursor;

        group.bench_function(format!("{}/full", shape.label()), |bencher| {
            bencher.iter_batched(
                || {
                    fence_queue(&sender);
                    assert_healthy(&state, &metrics);
                    batch.clone()
                },
                |events| {
                    events.publish(ehm_manager);
                    let expected_last = last_cursor
                        .checked_add(
                            u64::try_from(EVENTS_PER_SAMPLE).expect("sample size fits u64"),
                        )
                        .expect("cursor space");
                    fence_committed_through(
                        runtime,
                        committed_rx,
                        &state,
                        last_cursor,
                        expected_last,
                    );
                    std::hint::black_box(expected_last);
                },
                BatchSize::PerIteration,
            );
        });
        fence_queue(&ehm.sender);
        ehm.assert_healthy();
    }

    group.finish();
    ehm.shutdown();
}

criterion_group!(benches, manager_self_time, sqlite_end_to_end);
criterion_main!(benches);
