//! Allocator monotonicity + recovery ladder (ADR-0072).
//!
//! These pin the never-reused contract:
//!
//! - IDs continue monotonically after process restart against the same DB.
//! - A lagging sidecar is never used as allocator authority after DB /
//!   quarantine metadata loss; EHM enters pass-through instead.
//! - When all authoritative recovery paths fail AND a prior `.stale`
//!   exists, EHM enters pass-through (`required = false`) or refuses to
//!   start (`required = true`).

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
async fn shutdown_completes_even_with_live_sender_clones() {
    // Codex review regression test: shutdown must NOT depend on all
    // EventHistorySender clones being dropped. Producers commonly
    // hold a sender across the lifetime of the daemon; if shutdown
    // waited for the producer channel to close, the actor would
    // deadlock on rx.recv().
    //
    // Earlier PR2 implementation used `drop(self.sender)` + waited
    // for the channel-closed signal. Tests held sender clones in
    // their local scope, so shutdown hung. Fixed by switching to a
    // `watch::channel`-driven shutdown signal that lets the actor
    // exit while clones remain alive.
    let dir = TempDir::new().unwrap();
    let cfg = EventHistoryConfig {
        path: dir.path().join("events.db"),
        batch_interval: Duration::from_millis(5),
        ..EventHistoryConfig::default()
    };
    let manager = EventHistoryManager::start(cfg).await.unwrap();

    // Hold MULTIPLE clones across the shutdown call.
    let _live_clone_1 = manager.sender();
    let _live_clone_2 = manager.sender();
    let _live_clone_3 = manager.sender();

    // shutdown() must return within a reasonable time even with
    // sender clones still alive. Bound at 5 s — way above the
    // expected ms-scale teardown.
    tokio::time::timeout(Duration::from_secs(5), manager.shutdown())
        .await
        .expect("shutdown must not deadlock on live sender clones");
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
async fn stale_only_with_no_sidecar_refuses_to_restart_allocator_at_one() {
    // Codex review regression test for the critical bug pre-merge of PR2:
    //
    // Scenario: corrupt-DB + missing-sidecar on the first start
    // quarantines events.db → events.db.stale and returns PassThrough
    // (correct). The daemon exits. On the NEXT start, events.db
    // doesn't exist (it was renamed). The old open_with_recovery
    // would call Connection::open(path) which CREATES a fresh empty
    // DB, bootstrap seeds last_event_id=0, and the next event gets
    // event_id=1 — silently colliding with the prior process's IDs.
    //
    // Pinned behavior: when events.db is missing AND events.db.stale
    // exists AND no sidecar / quarantine-metadata anchor is
    // recoverable, refuse to start (required=true) or return
    // PassThrough (required=false). Never restart the allocator
    // silently.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");

    // First lifetime: leave a stale file with unrecoverable metadata
    // and NO sidecar. We do this by writing garbage to the events.db
    // path, then starting EHM, which quarantines it and returns
    // PassThrough.
    fs::write(&db_path, b"not a valid sqlite database").unwrap();
    let _ = fs::remove_file(dir.path().join("events.last_id"));
    let first_cfg = EventHistoryConfig {
        path: db_path.clone(),
        required: false,
        ..EventHistoryConfig::default()
    };
    let first_err = EventHistoryManager::start(first_cfg).await.unwrap_err();
    assert!(matches!(first_err, EventHistoryError::PassThrough));
    assert!(
        dir.path().join("events.db.stale").exists(),
        "stale quarantine produced"
    );
    assert!(!db_path.exists(), "primary DB renamed away by quarantine");
    assert!(
        !dir.path().join("events.last_id").exists(),
        "no sidecar to recover from"
    );

    // Second lifetime: primary DB missing, stale present, no sidecar.
    // Old code: probe_open would CREATE events.db, succeed, allocator
    // resets to 0 → first event gets event_id=1. New code: detect
    // stale-only state pre-create and return PassThrough.
    let second_cfg = EventHistoryConfig {
        path: db_path.clone(),
        required: false,
        ..EventHistoryConfig::default()
    };
    let second_err = EventHistoryManager::start(second_cfg).await.unwrap_err();
    assert!(
        matches!(second_err, EventHistoryError::PassThrough),
        "stale-only cold start must return PassThrough, got {second_err:?}"
    );

    // Same scenario with required=true must also refuse.
    let third_cfg = EventHistoryConfig {
        path: db_path.clone(),
        required: true,
        ..EventHistoryConfig::default()
    };
    let third_err = EventHistoryManager::start(third_cfg).await.unwrap_err();
    assert!(matches!(third_err, EventHistoryError::PassThrough));

    // No fresh DB created behind our back.
    assert!(!db_path.exists());
}

#[tokio::test]
async fn sidecar_only_with_no_db_refuses_to_restart_allocator_at_one() {
    // A sidecar without a primary DB is still evidence that IDs may have
    // been issued previously. Since the sidecar can lag committed
    // events, EHM must not use it to resume and must not create a fresh
    // DB starting at 1.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");
    fs::write(dir.path().join("events.last_id"), b"42\n").unwrap();

    let cfg = EventHistoryConfig {
        path: db_path.clone(),
        required: false,
        ..EventHistoryConfig::default()
    };
    let err = EventHistoryManager::start(cfg).await.unwrap_err();
    assert!(matches!(err, EventHistoryError::PassThrough));
    assert!(!db_path.exists(), "fresh DB must not be created");
}

#[tokio::test]
async fn corrupted_db_with_only_sidecar_refuses_to_resume_allocator() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");

    // First lifetime: flush a sidecar value. The sidecar may lag in
    // production, so even this exact-looking test sidecar is treated as
    // non-authoritative after DB/quarantine loss.
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

    // Required-false: do NOT resume from the sidecar. It is only a
    // diagnostic hint in v1; using it as allocator authority can reuse
    // committed IDs when the sidecar lags behind the DB.
    let cfg = EventHistoryConfig {
        path: db_path.clone(),
        batch_interval: Duration::from_millis(5),
        required: false,
        ..EventHistoryConfig::default()
    };
    let err = EventHistoryManager::start(cfg).await.unwrap_err();
    assert!(
        matches!(err, EventHistoryError::PassThrough),
        "sidecar alone must not authorize allocator restart, got {err:?}"
    );
}
