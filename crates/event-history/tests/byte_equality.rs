//! Byte-equality invariant — the must-have test for ADR-0072 PR2.
//!
//! The contract: what the producer hands EHM is what EHM persists in
//! the SQLite `payload` BLOB AND what EHM broadcasts on commit. Same
//! bytes. Always.
//!
//! This pins the durable side and the live side against drift —
//! prevents the whole class of "history says one thing, live stream
//! said another" bugs.

use std::sync::Arc;
use std::time::Duration;

use rustbgpd_event_history::{
    Category, EnvelopePeers, EventEnvelope, EventHistoryConfig, EventHistoryManager, PayloadCodec,
    QueryFilter, Severity,
};
use tempfile::TempDir;

fn make_envelope(seed: u8) -> EventEnvelope {
    EventEnvelope {
        timestamp_ns: 1_700_000_000_000_000_000_i64 + i64::from(seed),
        category: Category::Route,
        event_type: "added".to_string(),
        peers: EnvelopePeers {
            peer: Some("192.0.2.1".parse().unwrap()),
            previous_peer: None,
            target_peer: None,
        },
        afi_safi: Some("ipv4-unicast".to_string()),
        prefix: Some(format!("10.{seed}.0.0/24")),
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Opaque,
        // Distinctive payload — easy to assert byte-identity against.
        payload: (0..=seed)
            .flat_map(|n| [n, 0xAA, 0xBB, n.wrapping_add(1)])
            .collect(),
    }
}

#[tokio::test]
async fn payload_bytes_identical_persisted_and_broadcast() {
    let dir = TempDir::new().unwrap();
    let cfg = EventHistoryConfig {
        path: dir.path().join("events.db"),
        // Short batch interval so the test doesn't wait 50ms per event.
        batch_interval: Duration::from_millis(5),
        ..EventHistoryConfig::default()
    };
    let manager = EventHistoryManager::start(cfg).await.expect("start EHM");
    let sender = manager.sender();

    // Subscribe BEFORE sending so we observe every committed event.
    let mut sub = manager.subscribe();

    // Send three envelopes with distinctive payloads.
    let originals: Vec<EventEnvelope> = (1..=3).map(make_envelope).collect();
    for env in &originals {
        sender.try_send(env.clone()).expect("send");
    }

    // Collect broadcast deliveries.
    let mut broadcast_seen = Vec::new();
    for _ in 0..3 {
        let evt = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .expect("broadcast within 2s")
            .expect("broadcast recv");
        broadcast_seen.push(evt);
    }

    // Read back the same range from durable storage.
    let persisted = manager
        .query_persisted(0, u64::MAX, 100, QueryFilter::default())
        .await
        .expect("query");
    assert_eq!(persisted.len(), 3, "all three events persisted");

    // CORE INVARIANT: for each event_id, the bytes broadcast == bytes
    // persisted == bytes the producer originally provided.
    for (i, original) in originals.iter().enumerate() {
        let bcast = broadcast_seen.iter().find(|e| {
            // event_ids are assigned in input order
            e.event_id == (i as u64) + 1
        });
        let bcast = bcast.expect("matching broadcast event_id");
        let stored = persisted.iter().find(|p| p.event_id == bcast.event_id);
        let stored = stored.expect("matching persisted event_id");

        assert_eq!(
            original.payload, bcast.envelope.payload,
            "producer-input == broadcast (event_id {})",
            bcast.event_id
        );
        assert_eq!(
            original.payload, stored.payload,
            "producer-input == persisted (event_id {})",
            bcast.event_id
        );
        assert_eq!(
            stored.payload, bcast.envelope.payload,
            "persisted == broadcast (event_id {})",
            bcast.event_id
        );
    }

    // Same daemon_boot_id on every committed event (single process).
    let boot_id: Arc<str> = manager.daemon_boot_id();
    for evt in &broadcast_seen {
        assert_eq!(evt.daemon_boot_id.as_ref(), boot_id.as_ref());
    }
    for p in &persisted {
        assert_eq!(p.daemon_boot_id, boot_id.as_ref());
    }

    manager.shutdown().await;
}

#[tokio::test]
async fn payload_with_internal_zeros_and_high_bytes_survives_intact() {
    // Defend against any accidental string-ish handling: bytes
    // including 0x00, 0xFF, and arbitrary middle values.
    let dir = TempDir::new().unwrap();
    let cfg = EventHistoryConfig {
        path: dir.path().join("events.db"),
        batch_interval: Duration::from_millis(5),
        ..EventHistoryConfig::default()
    };
    let manager = EventHistoryManager::start(cfg).await.unwrap();

    let mut sub = manager.subscribe();
    let payload: Vec<u8> = (0..=255_u8).collect();
    let env = EventEnvelope {
        timestamp_ns: 0,
        category: Category::Policy,
        event_type: "set".to_string(),
        peers: EnvelopePeers::default(),
        afi_safi: None,
        prefix: None,
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Opaque,
        payload: payload.clone(),
    };
    manager.sender().try_send(env).unwrap();

    let evt = tokio::time::timeout(Duration::from_secs(2), sub.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evt.envelope.payload, payload);

    let persisted = manager
        .query_persisted(0, u64::MAX, 10, QueryFilter::default())
        .await
        .unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].payload, payload);

    manager.shutdown().await;
}

#[tokio::test]
async fn peer_filter_deduplicates_same_peer_in_multiple_roles() {
    let dir = TempDir::new().unwrap();
    let cfg = EventHistoryConfig {
        path: dir.path().join("events.db"),
        batch_interval: Duration::from_millis(5),
        ..EventHistoryConfig::default()
    };
    let manager = EventHistoryManager::start(cfg).await.unwrap();
    let peer = "192.0.2.10".parse().unwrap();

    let env = EventEnvelope {
        timestamp_ns: 0,
        category: Category::Route,
        event_type: "best-changed".to_string(),
        peers: EnvelopePeers {
            peer: Some(peer),
            previous_peer: Some(peer),
            target_peer: Some(peer),
        },
        afi_safi: Some("ipv4-unicast".to_string()),
        prefix: Some("203.0.113.0/24".to_string()),
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Opaque,
        payload: vec![1, 2, 3],
    };
    manager.sender().try_send(env).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let persisted = manager
        .query_persisted(
            0,
            u64::MAX,
            10,
            QueryFilter {
                peer: Some(peer.to_string()),
                ..QueryFilter::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].event_id, 1);

    manager.shutdown().await;
}

#[tokio::test]
async fn byte_cap_retention_evicts_oldest_rows_but_is_soft_size_target() {
    let dir = TempDir::new().unwrap();
    let cfg = EventHistoryConfig {
        path: dir.path().join("events.db"),
        batch_interval: Duration::from_millis(5),
        // Park the timer-driven retention far in the future: this
        // test drives the cap check explicitly via
        // `run_retention_pass`. Racing the interval timer against the
        // batch flush made the original shape flaky on loaded hosts
        // (the actor / storage thread could be starved past the fixed
        // sleep, so no pass observed the rows in time).
        retention_interval: Duration::from_secs(3600),
        max_events: 10_000,
        max_bytes: 1,
        ..EventHistoryConfig::default()
    };
    let manager = EventHistoryManager::start(cfg).await.unwrap();

    for i in 0..20_u8 {
        let mut env = make_envelope(i);
        env.payload = vec![i; 4096];
        manager.sender().try_send(env).unwrap();
    }

    // Wait (bounded) until all 20 rows are committed, so the retention
    // pass below deterministically sees every row. Commit is
    // guaranteed to happen; only its latency varies under load.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let committed = manager
            .query_persisted(0, u64::MAX, 100, QueryFilter::default())
            .await
            .unwrap()
            .len();
        if committed == 20 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {committed}/20 events committed before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Drive one retention pass explicitly — the same `StoreOp::Retain`
    // the interval timer would submit. `max_bytes: 1` can never be
    // satisfied (the SQLite file always has schema pages), so the
    // byte-cap loop must evict rows.
    let outcome = manager.run_retention_pass().await.unwrap();
    assert!(
        outcome.evicted_byte_cap > 0,
        "byte-cap retention pass should report evicted rows, got {outcome:?}"
    );

    let persisted = manager
        .query_persisted(0, u64::MAX, 100, QueryFilter::default())
        .await
        .unwrap();

    assert!(
        persisted.len() < 20,
        "byte-cap retention should evict rows even though SQLite file size is only a soft target"
    );

    manager.shutdown().await;
}
