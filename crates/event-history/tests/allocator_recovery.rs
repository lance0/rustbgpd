//! Allocator monotonicity + recovery ladder (ADR-0072).
//!
//! These pin the never-reused contract:
//!
//! - IDs continue monotonically after process restart against the same DB.
//! - After quarantine + sidecar fallback, IDs continue from the sidecar's
//!   high-water mark + 1 (no collision with the quarantined IDs).
//! - When all recovery paths fail AND a prior `.stale` exists, EHM enters
//!   pass-through (`required = false`) or refuses to start (`required = true`).

use std::fs;
use std::time::Duration;

use rustbgpd_event_history::{
    Category, EnvelopePeers, EventEnvelope, EventHistoryConfig, EventHistoryError,
    EventHistoryManager, PayloadCodec, QueryFilter, Severity,
};
use tempfile::TempDir;

fn make_envelope() -> EventEnvelope {
    EventEnvelope {
        timestamp_ns: 0,
        category: Category::Route,
        event_type: "added".into(),
        peers: EnvelopePeers::default(),
        afi_safi: None,
        prefix: None,
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Opaque,
        payload: vec![0xCA, 0xFE],
    }
}

async fn drain_and_count(manager: &EventHistoryManager) -> Vec<u64> {
    // Quick poll: storage is async; query directly.
    let persisted = manager
        .query_persisted(0, u64::MAX, 1000, QueryFilter::default())
        .await
        .unwrap();
    persisted.into_iter().map(|p| p.event_id).collect()
}

#[tokio::test]
async fn event_ids_monotonic_across_restart() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");

    // First lifetime: send 5 events, then shut down.
    {
        let cfg = EventHistoryConfig {
            path: db_path.clone(),
            batch_interval: Duration::from_millis(5),
            ..EventHistoryConfig::default()
        };
        let manager = EventHistoryManager::start(cfg).await.unwrap();
        let sender = manager.sender();
        for _ in 0..5 {
            sender.try_send(make_envelope()).unwrap();
        }
        // Wait for batch to commit (a query forces the round-trip).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let ids = drain_and_count(&manager).await;
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
        manager.shutdown().await;
    }

    // Second lifetime: send 5 more. event_ids must be 6..=10.
    {
        let cfg = EventHistoryConfig {
            path: db_path.clone(),
            batch_interval: Duration::from_millis(5),
            ..EventHistoryConfig::default()
        };
        let manager = EventHistoryManager::start(cfg).await.unwrap();
        for _ in 0..5 {
            manager.sender().try_send(make_envelope()).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let ids = drain_and_count(&manager).await;
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        manager.shutdown().await;
    }
}

#[tokio::test]
async fn corrupted_db_with_unrecoverable_anchor_and_required_true_refuses_start() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");

    // Create + populate, then shut down to flush.
    {
        let cfg = EventHistoryConfig {
            path: db_path.clone(),
            batch_interval: Duration::from_millis(5),
            sidecar_flush_interval_batches: u64::MAX, // never flush sidecar this run
            ..EventHistoryConfig::default()
        };
        let manager = EventHistoryManager::start(cfg).await.unwrap();
        manager.sender().try_send(make_envelope()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.shutdown().await;
    }

    // Corrupt the DB file beyond recoverability. We also delete the
    // sidecar so the recovery ladder has nothing to fall back on.
    fs::write(&db_path, b"this is not a valid sqlite database").unwrap();
    let sidecar = dir.path().join("events.last_id");
    let _ = fs::remove_file(&sidecar);

    // Required-true: refuse to start.
    let cfg = EventHistoryConfig {
        path: db_path.clone(),
        required: true,
        ..EventHistoryConfig::default()
    };
    let err = EventHistoryManager::start(cfg).await.unwrap_err();
    assert!(matches!(err, EventHistoryError::PassThrough));
    // Quarantine should have been created.
    assert!(dir.path().join("events.db.stale").exists());
}

#[tokio::test]
async fn corrupted_db_recovers_allocator_from_sidecar() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");

    // First lifetime: send enough events to flush the sidecar (default
    // is every 100 batches — we override to 1 so it flushes on every
    // commit). Then shutdown to ensure final sidecar flush.
    {
        let cfg = EventHistoryConfig {
            path: db_path.clone(),
            batch_interval: Duration::from_millis(5),
            sidecar_flush_interval_batches: 1,
            ..EventHistoryConfig::default()
        };
        let manager = EventHistoryManager::start(cfg).await.unwrap();
        for _ in 0..7 {
            manager.sender().try_send(make_envelope()).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        manager.shutdown().await;
    }

    // Sidecar should now exist and carry the high-water mark.
    let sidecar = dir.path().join("events.last_id");
    let sidecar_contents = fs::read_to_string(&sidecar).unwrap();
    let sidecar_value: u64 = sidecar_contents.trim().parse().unwrap();
    assert_eq!(sidecar_value, 7);

    // Corrupt the DB so the primary read fails AND the quarantine
    // also has unreadable metadata. We accomplish "unreadable
    // quarantine metadata" by replacing the DB with non-SQLite bytes —
    // the quarantine read will fail to open the file.
    fs::write(&db_path, b"\x00\x00garbage that is not sqlite").unwrap();

    // Required-false: continue. Allocator must start AFTER the sidecar
    // value, so the next event_id is 8.
    let cfg = EventHistoryConfig {
        path: db_path.clone(),
        batch_interval: Duration::from_millis(5),
        required: false,
        ..EventHistoryConfig::default()
    };
    let manager = EventHistoryManager::start(cfg).await.unwrap();
    assert!(
        manager.state().degraded(),
        "degraded flag set after quarantine"
    );

    manager.sender().try_send(make_envelope()).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let ids = drain_and_count(&manager).await;
    assert_eq!(
        ids,
        vec![8],
        "first post-recovery event picks up after sidecar high-water + 1"
    );

    manager.shutdown().await;
}
