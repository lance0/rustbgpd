//! Cursor API / actor-ordered handoff integration tests (PR3 of ADR-0072).
//!
//! These pin the contract that any event with
//! `from_event_id < event_id <= MAX` is delivered exactly once across
//! the replay → live handoff, regardless of whether the event was
//! committed before, during, or after the cursor capture.

use std::collections::HashSet;
use std::time::Duration;

use rustbgpd_event_history::{
    Category, EnvelopePeers, EventEnvelope, EventHistoryConfig, EventHistoryManager,
    EventSubscriptionItem, PayloadCodec, QueryFilter, Severity, SubscribeFilter, SubscribeRequest,
};
use tempfile::TempDir;

fn make_envelope(seed: u64) -> EventEnvelope {
    EventEnvelope {
        timestamp_ns: 1_700_000_000_000_000_000_i64 + seed as i64,
        category: Category::Route,
        event_type: "added".to_string(),
        peers: EnvelopePeers::default(),
        afi_safi: Some("ipv4-unicast".to_string()),
        prefix: Some(format!("10.0.{}.0/24", seed & 0xFF)),
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Opaque,
        payload: vec![(seed & 0xFF) as u8],
    }
}

fn fast_cfg(path: std::path::PathBuf) -> EventHistoryConfig {
    EventHistoryConfig {
        path,
        // Short batch interval so the test doesn't wait 50ms per event.
        batch_interval: Duration::from_millis(5),
        ..EventHistoryConfig::default()
    }
}

async fn drain_subscription(
    mut rx: tokio::sync::mpsc::Receiver<EventSubscriptionItem>,
    timeout: Duration,
    expected_at_least: usize,
) -> Vec<u64> {
    let mut ids = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while ids.len() < expected_at_least && tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(EventSubscriptionItem::Event(evt))) => ids.push(evt.event_id),
            Ok(Some(EventSubscriptionItem::Lagged(missed))) => {
                panic!("unexpected lag signal while draining test subscription: {missed}")
            }
            Ok(Some(EventSubscriptionItem::RetentionGap { missed, .. })) => {
                panic!("unexpected retention-gap signal while draining: missed={missed}")
            }
            Ok(Some(EventSubscriptionItem::Error(err))) => {
                panic!("unexpected subscription error while draining: {err}")
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if ids.len() >= expected_at_least {
        let grace_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        while tokio::time::Instant::now() < grace_deadline {
            let remaining = grace_deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(EventSubscriptionItem::Event(evt))) => ids.push(evt.event_id),
                Ok(Some(EventSubscriptionItem::Lagged(missed))) => {
                    panic!("unexpected lag signal while draining test subscription: {missed}")
                }
                Ok(Some(EventSubscriptionItem::RetentionGap { missed, .. })) => {
                    panic!("unexpected retention-gap signal while draining: missed={missed}")
                }
                Ok(Some(EventSubscriptionItem::Error(err))) => {
                    panic!("unexpected subscription error while draining: {err}")
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
    ids
}

#[tokio::test]
async fn subscribe_from_zero_drains_all_history() {
    let dir = TempDir::new().unwrap();
    let cfg = fast_cfg(dir.path().join("events.db"));
    let manager = EventHistoryManager::start(cfg).await.unwrap();

    let sender = manager.sender();
    for i in 1..=5_u64 {
        sender.try_send(make_envelope(i)).unwrap();
    }
    // Give the actor time to commit all 5 in one batch.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let req = SubscribeRequest {
        from_event_id: Some(0),
        ..SubscribeRequest::default()
    };
    let rx = manager
        .subscribe_from_event(req)
        .await
        .unwrap()
        .into_receiver();
    let ids = drain_subscription(rx, Duration::from_secs(2), 5).await;

    assert_eq!(ids, vec![1, 2, 3, 4, 5]);

    manager.shutdown().await;
}

#[tokio::test]
async fn subscribe_from_high_id_returns_only_new() {
    let dir = TempDir::new().unwrap();
    let manager = EventHistoryManager::start(fast_cfg(dir.path().join("events.db")))
        .await
        .unwrap();
    let sender = manager.sender();
    for i in 1..=10_u64 {
        sender.try_send(make_envelope(i)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Cursor past the existing high-water.
    let req = SubscribeRequest {
        from_event_id: Some(7),
        ..SubscribeRequest::default()
    };
    let rx = manager
        .subscribe_from_event(req)
        .await
        .unwrap()
        .into_receiver();
    let ids = drain_subscription(rx, Duration::from_secs(2), 3).await;

    assert_eq!(ids, vec![8, 9, 10]);

    manager.shutdown().await;
}

#[tokio::test]
async fn live_only_when_cursor_absent() {
    let dir = TempDir::new().unwrap();
    let manager = EventHistoryManager::start(fast_cfg(dir.path().join("events.db")))
        .await
        .unwrap();
    let sender = manager.sender();
    for i in 1..=3_u64 {
        sender.try_send(make_envelope(i)).unwrap();
    }
    // Deterministically wait until events 1-3 have committed rather than a fixed
    // sleep, which flakes on a slow CI runner. The live-only subscription's
    // high-watermark is `latest_event_id()` (see cursor.rs), so events 1-3 are
    // excluded only once committed; a too-short sleep lets subscribe capture a
    // watermark below 3 and replay them.
    let state = manager.state();
    let commit_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while state.latest_event_id() < 3 && tokio::time::Instant::now() < commit_deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        state.latest_event_id() >= 3,
        "events 1-3 should have committed before the live-only subscribe"
    );

    // Cursor absent → live-only. The 3 events already committed
    // should NOT be replayed; only events arriving after this call
    // should be delivered.
    let req = SubscribeRequest {
        from_event_id: None,
        ..SubscribeRequest::default()
    };
    let rx = manager
        .subscribe_from_event(req)
        .await
        .unwrap()
        .into_receiver();

    // Fire a fourth event AFTER subscribing.
    sender.try_send(make_envelope(4)).unwrap();

    let ids = drain_subscription(rx, Duration::from_secs(2), 1).await;
    assert_eq!(ids, vec![4]);

    manager.shutdown().await;
}

#[tokio::test]
async fn subscribe_during_active_commit_no_gap_no_dup() {
    // The hard semantic case: a synthetic producer is firing events
    // continuously while the subscribe call is in-flight. The
    // 3-step actor-ordered handoff must deliver every event in
    // (from_event_id, last_observed] exactly once.
    let dir = TempDir::new().unwrap();
    let manager = EventHistoryManager::start(fast_cfg(dir.path().join("events.db")))
        .await
        .unwrap();
    let sender = manager.sender();

    // Phase 1: seed with 50 events.
    for i in 1..=50_u64 {
        sender.try_send(make_envelope(i)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Phase 2: spawn a synthetic producer that keeps firing while we
    // call subscribe_from_event. The producer ramps the event_id
    // beyond 50 — those are the live-phase events.
    let sender_for_producer = sender.clone();
    let producer = tokio::spawn(async move {
        for i in 51..=150_u64 {
            // Best-effort try_send; if the queue fills, sleep briefly.
            while sender_for_producer.try_send(make_envelope(i)).is_err() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            // Yield so the actor can drain.
            if i % 10 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });

    // Cursor at 25 — we want events 26..=150 in order, no gaps, no
    // duplicates. The interesting region is around event 50: the
    // replay path covers [26, high_watermark] and the live path
    // covers (max(high_watermark, cursor), 150].
    let req = SubscribeRequest {
        from_event_id: Some(25),
        ..SubscribeRequest::default()
    };
    let rx = manager
        .subscribe_from_event(req)
        .await
        .unwrap()
        .into_receiver();

    producer.await.unwrap();
    // Wait a bit more to ensure the actor commits the tail of the
    // synthetic producer's events.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain — expect 26..=150 = 125 events.
    let ids = drain_subscription(rx, Duration::from_secs(3), 125).await;

    // Assertions: no gaps, no duplicates, all in range.
    let seen: HashSet<u64> = ids.iter().copied().collect();
    assert_eq!(
        seen.len(),
        ids.len(),
        "no duplicates allowed (saw {} ids, {} unique)",
        ids.len(),
        seen.len()
    );
    assert!(ids.iter().all(|&id| (26..=150).contains(&id)));

    // Strict monotonic.
    let mut prev = 25_u64;
    for &id in &ids {
        assert!(
            id > prev,
            "ids should be strictly monotonic; saw {id} after {prev}: full = {ids:?}"
        );
        prev = id;
    }

    // Coverage: every id in 26..=150 is present.
    for expected in 26..=150_u64 {
        assert!(
            seen.contains(&expected),
            "missing event_id {expected}; saw {} ids",
            ids.len()
        );
    }

    manager.shutdown().await;
}

#[tokio::test]
async fn filter_by_category_applies_to_replay_and_live() {
    let dir = TempDir::new().unwrap();
    let manager = EventHistoryManager::start(fast_cfg(dir.path().join("events.db")))
        .await
        .unwrap();
    let sender = manager.sender();

    // Mix of route + session events.
    for i in 1..=10_u64 {
        let mut env = make_envelope(i);
        env.category = if i % 2 == 0 {
            Category::Session
        } else {
            Category::Route
        };
        sender.try_send(env).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Cursor=0 with category=Route → expect odd-numbered ids only.
    let req = SubscribeRequest {
        from_event_id: Some(0),
        filter: SubscribeFilter {
            category: Some(Category::Route),
            ..SubscribeFilter::default()
        },
        ..SubscribeRequest::default()
    };
    let rx = manager
        .subscribe_from_event(req)
        .await
        .unwrap()
        .into_receiver();
    let ids = drain_subscription(rx, Duration::from_secs(2), 5).await;

    assert_eq!(ids, vec![1, 3, 5, 7, 9]);

    manager.shutdown().await;
}

#[tokio::test]
async fn invalid_high_from_id_returns_only_future_events() {
    // from_event_id beyond the current latest. Replay query returns
    // nothing; live path must not leak older event IDs from a batch-tail.
    let dir = TempDir::new().unwrap();
    let manager = EventHistoryManager::start(fast_cfg(dir.path().join("events.db")))
        .await
        .unwrap();
    let sender = manager.sender();
    for i in 1..=5_u64 {
        sender.try_send(make_envelope(i)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Cursor at 9999. Replay finds nothing. Then we send #6 — live
    // must suppress it because it is still <= caller cursor.
    let req = SubscribeRequest {
        from_event_id: Some(9999),
        ..SubscribeRequest::default()
    };
    let rx = manager
        .subscribe_from_event(req)
        .await
        .unwrap()
        .into_receiver();
    sender.try_send(make_envelope(6)).unwrap();

    let ids = drain_subscription(rx, Duration::from_millis(200), 1).await;
    assert!(
        ids.is_empty(),
        "events below from_event_id must not leak from live tail: {ids:?}"
    );

    manager.shutdown().await;
}

#[tokio::test]
async fn replay_preserves_payload_codec() {
    let dir = TempDir::new().unwrap();
    let manager = EventHistoryManager::start(fast_cfg(dir.path().join("events.db")))
        .await
        .unwrap();

    let mut env = make_envelope(1);
    env.payload_codec = PayloadCodec::Proto;
    manager.sender().try_send(env).unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut rx = manager
        .subscribe_from_event(SubscribeRequest {
            from_event_id: Some(0),
            ..SubscribeRequest::default()
        })
        .await
        .unwrap()
        .into_receiver();

    let evt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let EventSubscriptionItem::Event(evt) = evt else {
        panic!("unexpected lag signal");
    };
    assert_eq!(evt.envelope.payload_codec, PayloadCodec::Proto);

    manager.shutdown().await;
}

#[tokio::test]
async fn retention_gap_emits_as_leading_subscription_item_race_free() {
    // ADR-0072 PR5 review finding: the upfront `oldest_retained_event_id`
    // query that the gRPC handler did, followed by `subscribe_from_event`
    // starting a separate replay query, left a window where retention
    // could fire between the two storage ops and quietly move the floor
    // past the requested cursor without emitting a leading lag signal.
    //
    // This test pins the new contract: `subscribe_from_event` issues
    // `OldestEventId` + the first replay chunk in one storage-thread op
    // (`QueryWithFloor`), and emits the gap as `EventSubscriptionItem
    // ::RetentionGap` immediately before any replay rows. The
    // gRPC handler translates that to a leading `StreamLagEvent` on the
    // wire.
    let dir = TempDir::new().unwrap();
    let mut cfg = fast_cfg(dir.path().join("events.db"));
    cfg.max_events = 10;
    // Park timer-driven retention so the test controls exactly when
    // the count-cap pass observes the durable rows below.
    cfg.retention_interval = Duration::from_secs(3600);
    let manager = EventHistoryManager::start(cfg).await.unwrap();

    // Fill past the retention cap so id 1..N have been evicted by the
    // time we subscribe. Retain at most 10 events; emit 30 so the
    // floor is at least id 21.
    for i in 1..=30_u64 {
        loop {
            match manager.sender().try_send(make_envelope(i)) {
                Ok(()) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    }
    // Wait boundedly for all rows to become durable before issuing the
    // explicit pass. Removing this readiness barrier makes the exact
    // count-cap assertion below fail when retention races the appends.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let committed = manager
            .query_persisted(0, u64::MAX, 100, QueryFilter::default())
            .await
            .unwrap()
            .len();
        if committed == 30 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {committed}/30 events committed before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Run exactly one pass. Removing this pass leaves oldest=1 and
    // breaks the retained-floor assertion that protects the gap oracle.
    let outcome = manager.run_retention_pass().await.unwrap();
    assert_eq!(
        outcome.evicted_count_cap, 20,
        "one count-cap pass should evict exactly the 20 oldest rows"
    );

    let oldest_now = manager
        .handle()
        .oldest_retained_event_id()
        .await
        .unwrap()
        .expect("DB must not be empty after 30 commits");
    assert!(
        oldest_now > 1,
        "retention should have evicted at least id 1; got oldest={oldest_now}"
    );

    // Subscribe with a cursor that is below the live retained floor.
    // The first item on the stream MUST be a `RetentionGap` with the
    // exact missed count = oldest - from - 1.
    let from = 0_u64;
    let subscription = manager
        .subscribe_from_event(SubscribeRequest {
            from_event_id: Some(from),
            ..SubscribeRequest::default()
        })
        .await
        .unwrap();
    let mut rx = subscription.into_receiver();

    let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .expect("stream must yield at least the retention-gap item");
    let missed = match first {
        EventSubscriptionItem::RetentionGap {
            after_event_id,
            missed,
        } => {
            assert_eq!(after_event_id, from, "leading gap starts at the cursor");
            missed
        }
        EventSubscriptionItem::Event(evt) => {
            panic!(
                "expected leading RetentionGap, got Event id={}",
                evt.event_id
            )
        }
        EventSubscriptionItem::Lagged(n) => {
            panic!("expected leading RetentionGap, got Lagged({n})")
        }
        EventSubscriptionItem::Error(err) => {
            panic!("expected leading RetentionGap, got subscription error: {err}")
        }
    };
    assert_eq!(
        missed,
        oldest_now - from - 1,
        "missed must equal the global retention gap"
    );

    manager.shutdown().await;
}

#[tokio::test]
async fn slow_consumer_backpressures_without_dropping() {
    let dir = TempDir::new().unwrap();
    let manager = EventHistoryManager::start(fast_cfg(dir.path().join("events.db")))
        .await
        .unwrap();

    let subscription = manager
        .subscribe_from_event(SubscribeRequest {
            from_event_id: None,
            output_capacity: 1,
            ..SubscribeRequest::default()
        })
        .await
        .unwrap();
    let rx = subscription.into_receiver();

    for i in 1..=20_u64 {
        manager.sender().try_send(make_envelope(i)).unwrap();
    }

    let ids = drain_subscription(rx, Duration::from_secs(3), 20).await;
    assert_eq!(ids, (1..=20_u64).collect::<Vec<_>>());

    manager.shutdown().await;
}

// ── Retention eviction during replay ────────────────────────────────
//
// The seam is backpressure, not timing: `output_capacity = 1` gives a
// 64-row replay chunk behind a one-slot output channel, so once the
// test has received the first event the replay task is parked on
// `send` with chunk one already read and chunk two not yet queried.
// A retention pass issued at that point lands exactly between chunks.

const REPLAY_CHUNK: u64 = 64;

/// Commit `total` events (odd ids Route, even ids Session) with timer
/// retention parked, and return the manager once all are durable.
async fn start_with_committed(dir: &TempDir, total: u64, max_events: u64) -> EventHistoryManager {
    let mut cfg = fast_cfg(dir.path().join("events.db"));
    cfg.max_events = max_events;
    cfg.retention_interval = Duration::from_secs(3600);
    let manager = EventHistoryManager::start(cfg).await.unwrap();
    for i in 1..=total {
        let mut envelope = make_envelope(i);
        if i % 2 == 0 {
            envelope.category = Category::Session;
        }
        loop {
            match manager.sender().try_send(envelope.clone()) {
                Ok(()) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while manager.state().latest_event_id() < total {
        assert!(
            tokio::time::Instant::now() < deadline,
            "events not committed before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    manager
}

/// One received replay item, reduced to what the accounting needs.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Event(u64),
    Gap { after: u64, missed: u64 },
}

async fn next_seen(rx: &mut tokio::sync::mpsc::Receiver<EventSubscriptionItem>) -> Option<Seen> {
    match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        Ok(Some(EventSubscriptionItem::Event(evt))) => Some(Seen::Event(evt.event_id)),
        Ok(Some(EventSubscriptionItem::RetentionGap {
            after_event_id,
            missed,
        })) => Some(Seen::Gap {
            after: after_event_id,
            missed,
        }),
        Ok(Some(EventSubscriptionItem::Lagged(n))) => panic!("unexpected broadcast lag: {n}"),
        Ok(Some(EventSubscriptionItem::Error(err))) => panic!("unexpected error: {err}"),
        Ok(None) | Err(_) => None,
    }
}

/// Subscribe from 0 with a one-slot output, take the first event so
/// chunk one is known to be read, run `between_chunks`, then drain.
async fn replay_with_mid_replay_step<F, Fut>(
    manager: &EventHistoryManager,
    filter: SubscribeFilter,
    between_chunks: F,
) -> Vec<Seen>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut rx = manager
        .subscribe_from_event(SubscribeRequest {
            from_event_id: Some(0),
            filter,
            output_capacity: 1,
        })
        .await
        .unwrap()
        .into_receiver();
    let mut seen = vec![next_seen(&mut rx).await.expect("first replay item")];
    between_chunks().await;
    while let Some(item) = next_seen(&mut rx).await {
        seen.push(item);
    }
    seen
}

/// Every id in `1..=high_watermark` must be accounted for exactly once:
/// delivered, covered by a gap, or (under a filter) not matching.
/// Returns (delivered ids, total missed).
fn account(seen: &[Seen], high_watermark: u64, matches: impl Fn(u64) -> bool) -> (Vec<u64>, u64) {
    let mut cursor = 0_u64;
    let mut delivered = Vec::new();
    let mut missed_total = 0_u64;
    for item in seen {
        match *item {
            Seen::Event(id) => {
                assert!(id > cursor, "event {id} at or below cursor {cursor}");
                assert!(
                    (cursor + 1..id).all(|skipped| !matches(skipped)),
                    "matching ids in {}..{id} neither delivered nor covered by a gap",
                    cursor + 1
                );
                delivered.push(id);
                cursor = id;
            }
            Seen::Gap { after, missed } => {
                assert!(
                    (cursor + 1..=after).all(|skipped| !matches(skipped)),
                    "gap after {after} leaves matching ids above cursor {cursor} unaccounted"
                );
                assert!(
                    after >= cursor,
                    "gap after {after} re-covers cursor {cursor}"
                );
                assert!(missed > 0, "empty gap signal");
                missed_total += missed;
                cursor = after + missed;
            }
        }
    }
    assert!(cursor <= high_watermark, "accounted past the watermark");
    assert!(
        (cursor + 1..=high_watermark).all(|skipped| !matches(skipped)),
        "replay ended at {cursor} with matching ids up to {high_watermark} unaccounted"
    );
    (delivered, missed_total)
}

#[tokio::test]
async fn eviction_between_replay_chunks_is_signalled_as_a_gap() {
    let dir = TempDir::new().unwrap();
    let manager = start_with_committed(&dir, 200, 50).await;

    let seen = replay_with_mid_replay_step(&manager, SubscribeFilter::default(), || async {
        let outcome = manager.run_retention_pass().await.unwrap();
        assert_eq!(outcome.evicted_count_cap, 150, "floor must move to id 151");
    })
    .await;

    let (delivered, missed) = account(&seen, 200, |_| true);
    // Chunk one (1..=64) was read before the pass; 65..=150 were evicted
    // ahead of the cursor; 151..=200 survive.
    let expected: Vec<u64> = (1..=REPLAY_CHUNK).chain(151..=200).collect();
    assert_eq!(delivered, expected);
    assert_eq!(missed, 150 - REPLAY_CHUNK);
    assert_eq!(
        seen[REPLAY_CHUNK as usize],
        Seen::Gap {
            after: REPLAY_CHUNK,
            missed: 150 - REPLAY_CHUNK
        },
        "the gap must sit between the last chunk-one event and id 151"
    );

    manager.shutdown().await;
}

#[tokio::test]
async fn eviction_between_replay_chunks_is_signalled_under_a_category_filter() {
    let dir = TempDir::new().unwrap();
    let manager = start_with_committed(&dir, 400, 100).await;
    let filter = SubscribeFilter {
        category: Some(Category::Route),
        ..SubscribeFilter::default()
    };

    let seen = replay_with_mid_replay_step(&manager, filter, || async {
        let outcome = manager.run_retention_pass().await.unwrap();
        assert_eq!(outcome.evicted_count_cap, 300, "floor must move to id 301");
    })
    .await;

    let (delivered, missed) = account(&seen, 400, |id| id % 2 == 1);
    // Chunk one holds the first 64 Route rows (odd ids 1..=127). The
    // surviving Route rows start at 301, so consecutive delivered ids
    // alone (127 → 301) cannot reveal the loss; the floor does.
    let last_chunk_one = 2 * REPLAY_CHUNK - 1;
    let expected: Vec<u64> = (1..=last_chunk_one)
        .step_by(2)
        .chain((301..=400).step_by(2))
        .collect();
    assert_eq!(delivered, expected);
    // Global count, not the filtered subset: ids 128..=300.
    assert_eq!(missed, 300 - last_chunk_one);

    manager.shutdown().await;
}

#[tokio::test]
async fn eviction_of_everything_left_mid_replay_ends_with_a_gap() {
    let dir = TempDir::new().unwrap();
    let manager = start_with_committed(&dir, 200, 0).await;

    let seen = replay_with_mid_replay_step(&manager, SubscribeFilter::default(), || async {
        let outcome = manager.run_retention_pass().await.unwrap();
        assert_eq!(outcome.evicted_count_cap, 200, "table must be empty");
    })
    .await;

    let (delivered, missed) = account(&seen, 200, |_| true);
    assert_eq!(delivered, (1..=REPLAY_CHUNK).collect::<Vec<_>>());
    assert_eq!(missed, 200 - REPLAY_CHUNK);
    assert_eq!(
        seen.last(),
        Some(&Seen::Gap {
            after: REPLAY_CHUNK,
            missed: 200 - REPLAY_CHUNK
        }),
        "replay must end with the gap, not silently"
    );

    manager.shutdown().await;
}

#[tokio::test]
async fn multi_chunk_replay_without_eviction_has_no_gap_and_hands_off_to_live() {
    let dir = TempDir::new().unwrap();
    let manager = start_with_committed(&dir, 200, 1_000_000).await;

    // Commit more while replay is parked between chunks: these are
    // above the captured watermark and must arrive once, from live.
    let seen = replay_with_mid_replay_step(&manager, SubscribeFilter::default(), || async {
        for i in 201..=210_u64 {
            manager.sender().try_send(make_envelope(i)).unwrap();
        }
        while manager.state().latest_event_id() < 210 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;

    let expected: Vec<Seen> = (1..=210).map(Seen::Event).collect();
    assert_eq!(
        seen, expected,
        "no gap, no duplicate, no hole at the watermark"
    );

    manager.shutdown().await;
}

#[tokio::test]
async fn eviction_past_the_watermark_mid_replay_does_not_count_live_events() {
    let dir = TempDir::new().unwrap();
    let manager = start_with_committed(&dir, 200, 5).await;

    // Ten live events land, then retention keeps only 206..=210: the
    // floor is above the watermark (200). The gap must stop at 200;
    // 201..=210 still arrive from the live path.
    let seen = replay_with_mid_replay_step(&manager, SubscribeFilter::default(), || async {
        for i in 201..=210_u64 {
            manager.sender().try_send(make_envelope(i)).unwrap();
        }
        while manager.state().latest_event_id() < 210 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let outcome = manager.run_retention_pass().await.unwrap();
        assert_eq!(outcome.evicted_count_cap, 205);
    })
    .await;

    let (delivered, missed) = account(&seen, 210, |_| true);
    let expected: Vec<u64> = (1..=REPLAY_CHUNK).chain(201..=210).collect();
    assert_eq!(delivered, expected);
    assert_eq!(missed, 200 - REPLAY_CHUNK);

    manager.shutdown().await;
}
