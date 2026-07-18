//! `EventHistoryHandle` clone-independence + `oldest_retained_event_id` tests
//! (ADR-0072 PR5).
//!
//! The handle is the cloneable read/write projection of the
//! manager: producers and gRPC handlers each carry their own clone,
//! and dropping a clone must not affect any other clone's ability
//! to send + subscribe. Lifecycle (`shutdown`) stays on the manager
//! and is unaffected by handle drops.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustbgpd_event_history::{
    Category, EnvelopePeers, EventEnvelope, EventHistoryConfig, EventHistoryManager, PayloadCodec,
    Severity, SynchronousMode,
};
use tempfile::tempdir;

fn make_envelope(seq: u32) -> EventEnvelope {
    EventEnvelope {
        timestamp_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0),
        category: Category::Route,
        event_type: format!("test-event-{seq}"),
        peers: EnvelopePeers::default(),
        afi_safi: Some("ipv4-unicast".into()),
        prefix: Some(format!("10.{seq}.0.0/24")),
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Opaque,
        payload: vec![1, 2, 3, seq as u8],
    }
}

fn config_at(path: PathBuf) -> EventHistoryConfig {
    EventHistoryConfig {
        path,
        max_events: 100,
        max_bytes: 1_000_000,
        synchronous: SynchronousMode::Full,
        required: false,
        queue_capacity: 64,
        batch_size: 8,
        batch_interval: Duration::from_millis(20),
        broadcast_capacity: 64,
        retention_interval: Duration::from_secs(60),
        sidecar_flush_interval_batches: 100,
        metrics: None,
    }
}

#[tokio::test]
async fn clone_is_independent_of_original_handle() {
    let dir = tempdir().unwrap();
    let manager = EventHistoryManager::start(config_at(dir.path().join("events.db")))
        .await
        .expect("EHM start");

    // Take two handles. Drop the first; the second must still work.
    let first = manager.handle();
    let second = manager.handle();
    drop(first);

    // Sender from the surviving clone still enqueues.
    second
        .sender()
        .try_send(make_envelope(1))
        .expect("send via surviving handle clone");

    // Subscribe via the surviving clone. We accept any committed
    // event arriving; the actor commits the single envelope after
    // the batch interval elapses.
    let mut live = second.subscribe_live();
    let committed = tokio::time::timeout(Duration::from_secs(2), live.recv())
        .await
        .expect("commit within 2s")
        .expect("broadcast receiver still attached");
    assert_eq!(committed.envelope.event_type, "test-event-1");

    manager.shutdown().await;
}

#[tokio::test]
async fn oldest_retained_event_id_none_on_empty_db() {
    let dir = tempdir().unwrap();
    let manager = EventHistoryManager::start(config_at(dir.path().join("events.db")))
        .await
        .expect("EHM start");
    let handle = manager.handle();

    let oldest = handle
        .oldest_retained_event_id()
        .await
        .expect("query returns Ok on empty db");
    assert!(oldest.is_none(), "expected None on empty events table");

    manager.shutdown().await;
}

#[tokio::test]
async fn oldest_retained_event_id_matches_min_after_retention() {
    // Deterministic retention (LAN-476): the actor's interval timer
    // stays out of the picture (config_at's 60s never fires in-test).
    // Instead we observe all 50 commits on the live broadcast, then
    // drive one eviction pass explicitly via `run_retention_pass()`,
    // which is FIFO-ordered behind the appends on the storage thread.
    // No wall-clock sleeps, so host load cannot race the eviction.
    let dir = tempdir().unwrap();
    let mut cfg = config_at(dir.path().join("events.db"));
    cfg.max_events = 10;
    cfg.batch_size = 4;

    let manager = EventHistoryManager::start(cfg).await.expect("EHM start");
    let handle = manager.handle();

    // Subscribe BEFORE sending so every commit is observed (50 events
    // fit the broadcast capacity of 64 — no Lagged possible).
    let mut live = handle.subscribe_live();

    // Fill past the cap (50 events, cap=10). queue_capacity is 64, so
    // all 50 enqueue without the actor needing to drain first.
    for i in 0..50u32 {
        handle
            .sender()
            .try_send(make_envelope(i))
            .expect("queue holds all 50 events");
    }

    // Await all 50 commits — event-driven, not wall-clock. The
    // timeout is a hang backstop, not a race margin.
    for n in 0..50u32 {
        tokio::time::timeout(Duration::from_secs(30), live.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for commit {n}"))
            .expect("broadcast sender alive");
    }

    // One explicit retention pass evicts down to max_events.
    let outcome = manager
        .run_retention_pass()
        .await
        .expect("retention pass OK");
    assert!(
        outcome.evicted_count_cap > 0,
        "count-cap eviction evicted nothing with 50 events over cap 10"
    );

    let oldest = handle
        .oldest_retained_event_id()
        .await
        .expect("oldest query OK");
    // After retention, the oldest retained id is some value > 1
    // (we evicted at least the first batches). Exact value is
    // implementation-dependent; the invariant is that it's neither
    // None (table not empty) nor 1 (the original allocator floor).
    let oldest = oldest.expect("table not empty after 50 inserts");
    assert!(
        oldest > 1,
        "expected oldest_retained > 1 after eviction, got {oldest}"
    );

    manager.shutdown().await;
}
