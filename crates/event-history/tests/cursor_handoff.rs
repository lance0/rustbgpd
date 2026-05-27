//! Cursor API / actor-ordered handoff integration tests (PR3 of ADR-0072).
//!
//! These pin the contract that any event with
//! `from_event_id < event_id <= MAX` is delivered exactly once across
//! the replay → live handoff, regardless of whether the event was
//! committed before, during, or after the cursor capture.

use std::collections::HashSet;
use std::time::Duration;

use rustbgpd_event_history::{
    Category, EnvelopePeers, EventEnvelope, EventHistoryConfig, EventHistoryManager, PayloadCodec,
    Severity, SubscribeFilter, SubscribeRequest,
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
    mut rx: tokio::sync::mpsc::Receiver<rustbgpd_event_history::CommittedEvent>,
    timeout: Duration,
    expected_at_least: usize,
) -> Vec<u64> {
    let mut ids = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while ids.len() < expected_at_least && tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(evt)) => ids.push(evt.event_id),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if ids.len() >= expected_at_least {
        let grace_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        while tokio::time::Instant::now() < grace_deadline {
            let remaining = grace_deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(evt)) => ids.push(evt.event_id),
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
    tokio::time::sleep(Duration::from_millis(80)).await;

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
    assert_eq!(evt.envelope.payload_codec, PayloadCodec::Proto);

    manager.shutdown().await;
}

#[tokio::test]
async fn output_full_is_observable_in_subscription_stats() {
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
    let stats = subscription.stats();
    let _rx = subscription.into_receiver();

    for i in 1..=20_u64 {
        manager.sender().try_send(make_envelope(i)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert!(
        stats.snapshot().output_full > 0,
        "slow consumers should have observable output_full stats"
    );

    manager.shutdown().await;
}
