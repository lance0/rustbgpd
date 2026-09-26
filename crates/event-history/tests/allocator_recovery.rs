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
//! - A primary open failure is retried once before quarantine, and a
//!   quarantine never overwrites an earlier one.

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    // Regression test: shutdown must NOT depend on all EventHistorySender
    // clones being dropped. Producers commonly
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
    // Regression test for the critical bug pre-merge of PR2:
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

/// Count EHM's single retry of the primary open on this thread, and run
/// `also` at the same point.
///
/// This uses the crate's thread-local retry hook rather than a scoped
/// `tracing` subscriber on the retry's log line: callsite interest is cached
/// process-wide, so a sibling test that reaches the same callsite first with
/// no subscriber installed silently disables it for this thread too, and the
/// retry goes unobserved even though it happened.
fn count_probe_retries(mut also: impl FnMut() + 'static) -> Arc<AtomicUsize> {
    let retries = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&retries);
    rustbgpd_event_history::set_probe_retry_hook(move || {
        observed.fetch_add(1, Ordering::AcqRel);
        also();
    });
    retries
}

async fn write_committed_events(cfg: EventHistoryConfig, count: u8) {
    let manager = EventHistoryManager::start(cfg).await.unwrap();
    let mut committed = manager.subscribe();
    for _ in 0..count {
        manager.sender().try_send(make_envelope()).unwrap();
    }
    for _ in 0..count {
        tokio::time::timeout(Duration::from_secs(60), committed.recv())
            .await
            .expect("commit backstop elapsed")
            .unwrap();
    }
    manager.shutdown().await;
}

#[tokio::test]
async fn transient_primary_open_failure_is_retried_without_quarantine() {
    // Load-bearing break: without the retry the first failure quarantines a
    // healthy store and startup ends in pass-through.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");
    let cfg = EventHistoryConfig {
        path: db_path.clone(),
        batch_interval: Duration::from_millis(5),
        ..EventHistoryConfig::default()
    };
    write_committed_events(cfg.clone(), 3).await;

    // A directory where SQLite expects the WAL makes the next open of this
    // WAL-mode database fail. The hook removes it when EHM retries, so
    // exactly the first attempt fails.
    let wal = dir.path().join("events.db-wal");
    let _ = fs::remove_file(&wal);
    fs::create_dir(&wal).unwrap();
    let retries = count_probe_retries(move || {
        let _ = fs::remove_dir(&wal);
    });

    let manager = EventHistoryManager::start(cfg)
        .await
        .expect("a transient open failure must not reach the recovery ladder");
    assert_eq!(
        retries.load(Ordering::Acquire),
        1,
        "the first open must fail and be retried once"
    );
    assert!(!dir.path().join("events.db.stale").exists());
    assert!(!manager.state().degraded());
    assert_eq!(drain_and_count(&manager).await, vec![1, 2, 3]);
    manager.shutdown().await;
}

#[tokio::test]
async fn repeated_open_failure_quarantines_and_keeps_the_earlier_copy() {
    // Load-bearing break: overwriting the existing quarantine destroys the
    // earlier forensic copy.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("events.db");
    fs::write(dir.path().join("events.db.stale"), b"earlier copy").unwrap();
    fs::write(dir.path().join("events.db.stale-wal"), b"earlier wal").unwrap();
    fs::write(&db_path, b"not a valid sqlite database").unwrap();
    let retries = count_probe_retries(|| {});

    let err = EventHistoryManager::start(EventHistoryConfig {
        path: db_path.clone(),
        required: false,
        ..EventHistoryConfig::default()
    })
    .await
    .unwrap_err();
    // The new quarantine carries no allocator anchor, so prior-allocation
    // evidence forces pass-through.
    assert!(matches!(err, EventHistoryError::PassThrough));
    assert_eq!(retries.load(Ordering::Acquire), 1);
    assert!(!db_path.exists());
    let read = |name: &str| fs::read(dir.path().join(name)).unwrap();
    assert_eq!(read("events.db.stale"), b"not a valid sqlite database");
    assert_eq!(read("events.db.stale.1"), b"earlier copy");
    assert_eq!(read("events.db.stale.1-wal"), b"earlier wal");
    assert!(!dir.path().join("events.db.stale-wal").exists());
}

/// Every file in `dir` with its bytes (`None` when unreadable), for
/// asserting that a failed start left the store exactly as it found it.
fn snapshot_files(dir: &std::path::Path) -> Vec<(String, Option<Vec<u8>>)> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read(&path).ok())
        })
        .collect();
    files.sort();
    files
}

/// An intact store with three committed events, plus its config.
async fn intact_store() -> (TempDir, EventHistoryConfig) {
    let dir = TempDir::new().unwrap();
    let cfg = EventHistoryConfig {
        path: dir.path().join("events.db"),
        batch_interval: Duration::from_millis(5),
        ..EventHistoryConfig::default()
    };
    write_committed_events(cfg.clone(), 3).await;
    (dir, cfg)
}

/// Start against a store the host will not let EHM open, on the first open
/// and on the retry, and assert that the store is left exactly in place.
async fn assert_host_error_leaves_store_in_place(dir: &TempDir, cfg: &EventHistoryConfig) {
    let before = snapshot_files(dir.path());
    let retries = count_probe_retries(|| {});

    for required in [true, false] {
        let err = EventHistoryManager::start(EventHistoryConfig {
            required,
            ..cfg.clone()
        })
        .await
        .expect_err("a store the host will not open must not start");
        assert!(
            matches!(err, EventHistoryError::Sqlite(_)),
            "the host error must reach startup, got {err:?}"
        );
    }
    assert_eq!(
        retries.load(Ordering::Acquire),
        2,
        "each start retries once"
    );
    let quarantined: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.contains("stale"))
        .collect();
    assert!(
        quarantined.is_empty(),
        "an intact store must not be quarantined: {quarantined:?}"
    );
    // SQLite may leave empty side files behind when it opens a store
    // read-only; every file that was there must be byte-for-byte intact.
    let after = snapshot_files(dir.path());
    for file in &before {
        assert!(after.contains(file), "{} changed or moved", file.0);
    }
}

/// Once the host condition clears, the same store opens with its history.
async fn assert_store_reopens_intact(cfg: EventHistoryConfig) {
    let manager = EventHistoryManager::start(cfg).await.unwrap();
    assert!(!manager.state().degraded());
    assert_eq!(drain_and_count(&manager).await, vec![1, 2, 3]);
    manager.shutdown().await;
}

#[tokio::test]
async fn unopenable_wal_leaves_an_intact_store_in_place() {
    // Load-bearing break: a side file the host will not let SQLite open
    // (EISDIR here, EACCES for a root-owned file) failed both attempts,
    // so the intact store was quarantined as corrupt.
    let (dir, cfg) = intact_store().await;
    let wal = dir.path().join("events.db-wal");
    let _ = fs::remove_file(&wal);
    fs::create_dir(&wal).unwrap();

    assert_host_error_leaves_store_in_place(&dir, &cfg).await;

    fs::remove_dir(&wal).unwrap();
    assert_store_reopens_intact(cfg).await;
}

/// Whether permissions deny this process a write to `probe`; with
/// `CAP_DAC_OVERRIDE` (root) they do not, and the permission cases have
/// nothing to test.
#[cfg(unix)]
fn permissions_bind(probe: &std::path::Path) -> bool {
    let existed = probe.exists();
    let bind = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(probe)
        .is_err();
    if !bind {
        if !existed {
            fs::remove_file(probe).unwrap();
        }
        eprintln!("skipping: file permissions do not bind this process");
    }
    bind
}

#[cfg(unix)]
#[tokio::test]
async fn read_only_store_file_refuses_to_start() {
    use std::os::unix::fs::PermissionsExt;

    // A root-owned events.db: SQLite opens it read-only, and an existing
    // store bootstraps without writing, so startup used to succeed and
    // the first append degraded the log.
    let (dir, cfg) = intact_store().await;
    fs::set_permissions(&cfg.path, fs::Permissions::from_mode(0o444)).unwrap();
    if !permissions_bind(&cfg.path) {
        return;
    }

    assert_host_error_leaves_store_in_place(&dir, &cfg).await;

    // SQLite created the side files with the database file's mode, so the
    // operator's fix covers the whole set, as it would for a chown.
    for entry in fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_store_reopens_intact(cfg).await;
}

#[cfg(unix)]
#[tokio::test]
async fn root_owned_side_files_leave_an_intact_store_in_place() {
    use std::os::unix::fs::PermissionsExt;

    // Side files left by a manual run as root: the daemon's user can
    // neither read nor write them.
    let (dir, cfg) = intact_store().await;
    let side = [
        dir.path().join("events.db-wal"),
        dir.path().join("events.db-shm"),
    ];
    for file in &side {
        fs::write(file, b"").unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o000)).unwrap();
    }
    if !permissions_bind(&side[0]) {
        return;
    }

    assert_host_error_leaves_store_in_place(&dir, &cfg).await;

    for file in &side {
        fs::remove_file(file).unwrap();
    }
    assert_store_reopens_intact(cfg).await;
}

#[cfg(unix)]
#[tokio::test]
async fn read_only_state_dir_leaves_an_intact_store_in_place() {
    use std::os::unix::fs::PermissionsExt;

    // A read-only state directory (a read-only remount, or a directory the
    // daemon's user cannot write): SQLite cannot create the WAL.
    let (dir, cfg) = intact_store().await;
    let set_mode = |mode| {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
    };
    set_mode(0o555);
    if !permissions_bind(&dir.path().join("probe")) {
        set_mode(0o755);
        return;
    }

    assert_host_error_leaves_store_in_place(&dir, &cfg).await;

    set_mode(0o755);
    assert_store_reopens_intact(cfg).await;
}
