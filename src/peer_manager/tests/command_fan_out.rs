//! Sweeps over many peers send their session commands concurrently, under one
//! command window, while serving readiness.
//!
//! A session parked on a full RIB mailbox (ADR-0078) stops draining its
//! command channel, so every bounded command to it costs the whole deadline.
//! Each test wedges every session that way and requires the sweep to end one
//! window after it starts, not one window per peer, with a readiness probe
//! answered inside the 200 ms readiness deadline meanwhile.

use super::*;
use rustbgpd_api::peer_types::{
    PeerManagerReadinessQuery, PeerReconcileEffect, ReconcileFailureKind,
};
use rustbgpd_rib::PeerId;
use rustbgpd_transport::PeerCommand;
use std::collections::HashSet;

const WEDGED: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 12)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 13)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 14)),
];

/// `PEER_LIFECYCLE_COMMAND_TIMEOUT` and `PEER_POLICY_UPDATE_TIMEOUT`.
const WINDOW: Duration = Duration::from_millis(500);

/// A session parked on a full RIB mailbox: its only command slot is taken
/// and it never reads its channel again.
fn wedged_session() -> PeerHandle {
    let (commands, receiver) = mpsc::channel(1);
    commands
        .try_send(PeerCommand::Start)
        .expect("fill the only command slot");
    let task = tokio::spawn(async move {
        let _receiver = receiver;
        std::future::pending::<Result<(), rustbgpd_transport::TransportError>>().await
    });
    PeerHandle::from_parts(commands, task)
}

async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// Advance paused time 1 ms at a time, settling after each step, so a sweep
/// phase that starts when an earlier one times out starts its timers at the
/// right instant rather than at the end of one long jump.
async fn advance_settled(by: Duration) {
    for _ in 0..by.as_millis() {
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
    }
}

/// Run `sweep` with a readiness probe already queued, and send another once
/// it is waiting on its wedged sessions. Each probe must be answered without
/// time passing; the sweep must still be running 1 ms before one `window`
/// ends and finished when it does. A sequential sweep takes one window per
/// wedged peer, and one that does not serve readiness while it waits leaves
/// the second probe waiting for all of them.
async fn one_readiness_serving_window<T: Send + 'static>(
    readiness_tx: &mpsc::Sender<PeerManagerReadinessQuery>,
    window: Duration,
    sweep: impl Future<Output = T> + Send + 'static,
) -> T {
    let (reply, mut response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    let sweep = tokio::spawn(sweep);
    settle().await;
    assert!(
        response.try_recv().is_ok(),
        "readiness queued before the sweep must be answered as it starts waiting"
    );
    let probe = window * 3 / 10;
    advance_settled(probe).await;
    let (reply, mut response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    settle().await;
    assert!(
        response.try_recv().is_ok(),
        "readiness must be answered while the sweep waits on wedged sessions"
    );
    advance_settled(window.saturating_sub(probe + Duration::from_millis(1))).await;
    assert!(
        !sweep.is_finished(),
        "the sweep waits for the wedged sessions' command window"
    );
    advance_settled(Duration::from_millis(1)).await;
    assert!(
        sweep.is_finished(),
        "every wedged session shares one {window:?} command window"
    );
    sweep.await.unwrap()
}

fn readiness_manager(mgr: PeerManager) -> (PeerManager, mpsc::Sender<PeerManagerReadinessQuery>) {
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    (mgr.with_readiness_queries(readiness_rx), readiness_tx)
}

/// A peer-group change bounces every dynamic member at once.
#[tokio::test(start_paused = true)]
async fn peer_group_bounce_signals_wedged_dynamic_members_in_one_window() {
    let (mut mgr, readiness_tx) = readiness_manager(dynamic_test_manager());
    let range = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
    for (session_id, addr) in (1..).zip(WEDGED) {
        insert_test_dynamic_managed_peer(
            &mut mgr,
            addr,
            session_id,
            wedged_session(),
            true,
            range,
            8,
            "ix-members",
        );
    }
    let target = DynamicRangeTarget {
        addr: range,
        prefix_len: 8,
        peer_group: "ix-members".to_string(),
    };
    let outcome = one_readiness_serving_window(&readiness_tx, WINDOW, async move {
        mgr.bounce_dynamic_peers_for_ranges(std::slice::from_ref(&target), &[])
            .await
    })
    .await;
    assert_eq!(outcome.signaled, 0);
    assert_eq!(
        outcome.failures,
        WEDGED
            .iter()
            .map(|addr| format!("{addr}: stop timed out after 500ms"))
            .collect::<Vec<_>>(),
        "failures are reported in peer order"
    );
}

/// A rollback reaps every dynamic peer its restored ranges no longer admit.
#[tokio::test(start_paused = true)]
async fn rollback_reap_joins_wedged_dynamic_peers_in_one_window() {
    let (mut mgr, readiness_tx) = readiness_manager(dynamic_test_manager());
    let range = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
    for (session_id, addr) in (1..).zip(WEDGED) {
        insert_test_dynamic_managed_peer(
            &mut mgr,
            addr,
            session_id,
            wedged_session(),
            true,
            range,
            8,
            "ix-members",
        );
    }
    mgr.dynamic_ranges.clear();
    let (removed, mgr) = one_readiness_serving_window(&readiness_tx, WINDOW, async move {
        let removed = mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await;
        (removed, mgr)
    })
    .await;
    assert_eq!(removed, WEDGED.len());
    assert!(mgr.peers.is_empty());
    assert_eq!(mgr.dynamic_peer_count, 0);
}

/// A SIGHUP reconcile removes and replaces wedged static peers in one window;
/// each changed peer is re-added only after its old session is gone.
#[tokio::test(start_paused = true)]
async fn sighup_reconcile_removes_wedged_peers_in_one_window() {
    let (mut mgr, readiness_tx) = readiness_manager(test_peer_manager());
    for addr in WEDGED {
        insert_test_managed_peer(&mut mgr, addr, wedged_session(), false);
    }
    let removed = keys(WEDGED[..2].iter().copied());
    let changed: Vec<_> = WEDGED[2..]
        .iter()
        .map(|&addr| {
            let mut config = make_config(addr, 65002);
            config.description = "replaced".to_string();
            config
        })
        .collect();
    let (outcome, mgr) = one_readiness_serving_window(&readiness_tx, WINDOW, async move {
        let outcome = mgr.reconcile_peers(Vec::new(), removed, changed).await;
        (outcome, mgr)
    })
    .await;
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    assert_eq!(
        outcome.effects,
        vec![
            PeerReconcileEffect::Removed(key(WEDGED[0])),
            PeerReconcileEffect::Removed(key(WEDGED[1])),
            PeerReconcileEffect::Replaced(key(WEDGED[2])),
            PeerReconcileEffect::Replaced(key(WEDGED[3])),
        ]
    );
    assert_eq!(
        mgr.peers.keys().cloned().collect::<BTreeSet<_>>(),
        keys(WEDGED[2..].iter().copied()).into_iter().collect()
    );
    for addr in &WEDGED[2..] {
        assert_eq!(mgr.peers[&key(*addr)].description, "replaced");
    }
}

/// A SIGHUP reconcile that changes changed peers' discard list purge-resets
/// them all at once before their deletes: one window for the purges, then
/// one for the deletes. A peer whose purge is not admitted stays installed
/// with its old config.
#[tokio::test(start_paused = true)]
async fn sighup_reconcile_purges_changed_peers_in_one_window() {
    let healthy = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 15));
    let (mut mgr, readiness_tx) = readiness_manager(test_peer_manager());
    for addr in WEDGED {
        insert_test_managed_peer(&mut mgr, addr, wedged_session(), false);
    }
    insert_test_managed_peer(&mut mgr, healthy, draining_session(), false);
    let removed = keys(WEDGED[..2].iter().copied());
    let changed: Vec<_> = WEDGED[2..]
        .iter()
        .copied()
        .chain([healthy])
        .map(|addr| {
            let mut config = make_config(addr, 65002);
            config.description = "replaced".to_string();
            config.discard_path_attributes = std::sync::Arc::from([16_u8]);
            config
        })
        .collect();
    let (outcome, mgr) = one_readiness_serving_window(&readiness_tx, 2 * WINDOW, async move {
        let outcome = mgr.reconcile_peers(Vec::new(), removed, changed).await;
        (outcome, mgr)
    })
    .await;
    assert_eq!(
        outcome.effects,
        vec![
            PeerReconcileEffect::Removed(key(WEDGED[0])),
            PeerReconcileEffect::Removed(key(WEDGED[1])),
            PeerReconcileEffect::Replaced(key(healthy)),
        ]
    );
    assert_eq!(
        outcome
            .failures
            .iter()
            .map(|failure| (failure.kind, failure.peer.clone()))
            .collect::<Vec<_>>(),
        vec![
            (ReconcileFailureKind::ChangeRemove, key(WEDGED[2])),
            (ReconcileFailureKind::ChangeRemove, key(WEDGED[3])),
        ]
    );
    assert!(
        outcome.failures.iter().all(|failure| failure
            .error
            .contains("failed to purge-reset primary session")),
        "{:?}",
        outcome.failures
    );
    assert_eq!(mgr.peers[&key(healthy)].description, "replaced");
    for addr in &WEDGED[2..] {
        assert_ne!(
            mgr.peers[&key(*addr)].description,
            "replaced",
            "an unpurged peer keeps its old config"
        );
    }
}

/// A session that acknowledges every graceful-shutdown toggle.
fn acking_gshut_session() -> PeerHandle {
    let (commands, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            if let PeerCommand::UpdateGracefulShutdown { reply, .. } = command {
                let _ = reply.send(Ok(()));
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

/// The global graceful-shutdown toggle reaches every peer in one window, then
/// refreshes each acknowledging peer with its own RIB command, so the RIB
/// replays one peer's table per turn.
#[tokio::test(start_paused = true)]
async fn global_graceful_shutdown_toggles_wedged_peers_in_one_window() {
    let healthy = [
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 21)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 22)),
    ];
    let (_commands_tx, commands_rx) = mpsc::channel(4);
    let (rib_tx, mut rib_rx) = mpsc::channel(16);
    let refreshed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = refreshed.clone();
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::RefreshPeerOutbound { peer, reply } = update {
                recorded.lock().unwrap().push(vec![peer]);
                let _ = reply.send(Ok(()));
            }
        }
    });
    let (mut mgr, readiness_tx) = readiness_manager(PeerManager::new(
        commands_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    ));
    for addr in WEDGED {
        insert_test_managed_peer(&mut mgr, addr, wedged_session(), false);
    }
    for addr in healthy {
        insert_test_managed_peer(&mut mgr, addr, acking_gshut_session(), false);
    }
    let (result, mgr) = one_readiness_serving_window(&readiness_tx, WINDOW, async move {
        let result = mgr.set_graceful_shutdown(None, true).await;
        (result, mgr)
    })
    .await;
    let error = result
        .expect_err("wedged sessions fail their toggle")
        .to_string();
    for addr in WEDGED {
        assert!(error.contains(&format!("{addr}: session:")), "{error}");
    }
    assert!(
        mgr.peers
            .values()
            .all(|managed| managed.advertise_graceful_shutdown),
        "desired state is stored for every peer"
    );
    let refreshed = refreshed.lock().unwrap();
    assert!(
        refreshed.iter().all(|peers| peers.len() == 1),
        "each acknowledging peer is refreshed by its own RIB command: {refreshed:?}"
    );
    assert_eq!(
        refreshed.iter().flatten().copied().collect::<HashSet<_>>(),
        healthy
            .iter()
            .map(|&addr| mgr.rib_peer_of(&key(addr)))
            .collect::<HashSet<_>>(),
    );
}

const GSHUT_HEALTHY: [IpAddr; 3] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 31)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 32)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 33)),
];

/// `GSHUT_HEALTHY` acknowledging peers, with the RIB's receiving end and a
/// sender standing for the sessions' route updates.
fn gshut_manager_with_rib_queue() -> (
    PeerManager,
    mpsc::Receiver<RibUpdate>,
    mpsc::Sender<RibUpdate>,
) {
    let (_commands_tx, commands_rx) = mpsc::channel(4);
    let (rib_tx, rib_rx) = mpsc::channel(16);
    let sessions_rib_tx = rib_tx.clone();
    let mut mgr = PeerManager::new(
        commands_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for addr in GSHUT_HEALTHY {
        insert_test_managed_peer(&mut mgr, addr, acking_gshut_session(), false);
    }
    (mgr, rib_rx, sessions_rib_tx)
}

/// The toggle replies once the sessions acknowledge; the outbound refreshes
/// follow one peer at a time, each sent only after the RIB answers the one
/// before. A route update a session sends after the toggle therefore reaches
/// the RIB ahead of the second peer's full-table replay instead of behind
/// every replay.
#[tokio::test(start_paused = true)]
async fn gshut_refreshes_interleave_with_later_route_updates() {
    let (mut mgr, mut rib_rx, sessions_rib_tx) = gshut_manager_with_rib_queue();
    let toggle = tokio::spawn(async move {
        let result = mgr.set_graceful_shutdown(None, true).await;
        (result, mgr)
    });
    settle().await;
    assert!(
        toggle.is_finished(),
        "the toggle replies without waiting for the outbound refreshes"
    );
    let (result, _mgr) = toggle.await.unwrap();
    result.expect("every session acknowledged");

    let Ok(RibUpdate::RefreshPeerOutbound { reply: first, .. }) = rib_rx.try_recv() else {
        panic!("the first outbound refresh is sent");
    };
    assert!(
        rib_rx.try_recv().is_err(),
        "one outbound refresh in flight at a time"
    );
    let withdrawn_by = PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 99)));
    sessions_rib_tx
        .send(RibUpdate::PeerDown {
            peer: withdrawn_by,
            session_id: 9,
        })
        .await
        .unwrap();
    first.send(Ok(())).unwrap();
    settle().await;
    assert!(
        matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { peer, .. }) if peer == withdrawn_by),
        "the later route update is ahead of the next replay"
    );
    let mut refreshed = 1;
    while let Ok(RibUpdate::RefreshPeerOutbound { reply, .. }) = rib_rx.try_recv() {
        assert!(rib_rx.try_recv().is_err(), "still one at a time");
        reply.send(Ok(())).unwrap();
        refreshed += 1;
        settle().await;
    }
    assert_eq!(
        refreshed,
        GSHUT_HEALTHY.len(),
        "every peer is refreshed once"
    );
}

/// The toggle never waits on the RIB: one that never answers neither delays
/// nor fails it.
#[tokio::test(start_paused = true)]
async fn gshut_does_not_wait_for_a_rib_that_never_answers() {
    let (mut mgr, _rib_rx, _sessions_rib_tx) = gshut_manager_with_rib_queue();
    let started = tokio::time::Instant::now();
    mgr.set_graceful_shutdown(None, true)
        .await
        .expect("a stuck refresh is not a toggle failure");
    assert_eq!(started.elapsed(), Duration::ZERO);
}

fn validation_dependents() -> (PeerManager, mpsc::Sender<PeerManagerReadinessQuery>) {
    let (mut mgr, readiness_tx) = readiness_manager(test_peer_manager());
    for addr in WEDGED {
        insert_test_managed_peer(&mut mgr, addr, wedged_session(), false);
        mgr.peers.get_mut(&key(addr)).unwrap().import_policy =
            Some(validation_policy_chain(ImportValidationDependency::Rpki));
    }
    (mgr, readiness_tx)
}

/// An RTR delta asks every RPKI-dependent session to re-evaluate locally
/// (RFC 9324) at once; each wedged one falls back to a pending refresh.
#[tokio::test(start_paused = true)]
async fn rtr_delta_revalidates_wedged_dependents_in_one_window() {
    let (mut mgr, readiness_tx) = validation_dependents();
    let (result, mgr) = one_readiness_serving_window(&readiness_tx, WINDOW, async move {
        let result = mgr
            .revalidate_import_validation_dependents(rustbgpd_transport::ValidationDelta::Rpki(
                None,
            ))
            .await;
        (result, mgr)
    })
    .await;
    let error = result.expect_err("wedged dependents fail");
    assert!(
        error.contains("failed for 4 of 4 eligible peers"),
        "{error}"
    );
    assert!(
        mgr.peers.values().all(|managed| managed.pending_refresh),
        "an unanswered dependent keeps a pending refresh"
    );
}

/// Without local re-evaluation, every dependent's state probe shares one
/// `PEER_QUERY_TIMEOUT` window.
#[tokio::test(start_paused = true)]
async fn rtr_delta_probes_wedged_dependents_in_one_window() {
    let (mut mgr, readiness_tx) = validation_dependents();
    let (result, mgr) =
        one_readiness_serving_window(&readiness_tx, PEER_QUERY_TIMEOUT, async move {
            let result = mgr
                .soft_reset_import_validation_dependents(ImportValidationDependency::Rpki)
                .await;
            (result, mgr)
        })
        .await;
    let error = result.expect_err("wedged dependents fail");
    assert!(
        error.contains("failed for 4 of 4 eligible peers"),
        "{error}"
    );
    assert!(mgr.peers.values().all(|managed| managed.pending_refresh));
}

/// A session that reads every command and answers none.
fn draining_session() -> PeerHandle {
    let (commands, mut receiver) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

/// 65 dynamic members of one range, in address order, wedged at positions 0
/// and 64 and draining their commands everywhere else: more members than
/// `PEER_SHUTDOWN_CONCURRENCY`, so a sweep that starts a member only when
/// the one 64 places before it has finished takes two windows.
fn dynamic_members_wedged_64_apart() -> (PeerManager, mpsc::Sender<PeerManagerReadinessQuery>) {
    let (mut mgr, readiness_tx) = readiness_manager(dynamic_test_manager());
    let range = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
    for index in 0..=64_u8 {
        let handle = if index % 64 == 0 {
            wedged_session()
        } else {
            draining_session()
        };
        insert_test_dynamic_managed_peer(
            &mut mgr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 1, index)),
            u64::from(index) + 1,
            handle,
            true,
            range,
            8,
            "ix-members",
        );
    }
    (mgr, readiness_tx)
}

/// A single command per member: wedged members anywhere in a sweep larger
/// than the concurrency cap still share one window.
#[tokio::test(start_paused = true)]
async fn bounce_beyond_the_concurrency_cap_still_takes_one_window() {
    let (mut mgr, readiness_tx) = dynamic_members_wedged_64_apart();
    let target = DynamicRangeTarget {
        addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        prefix_len: 8,
        peer_group: "ix-members".to_string(),
    };
    let outcome = one_readiness_serving_window(&readiness_tx, WINDOW, async move {
        mgr.bounce_dynamic_peers_for_ranges(std::slice::from_ref(&target), &[])
            .await
    })
    .await;
    assert_eq!(outcome.signaled, 63);
    assert_eq!(outcome.failures.len(), 2, "{:?}", outcome.failures);
}

/// Command chains beyond the concurrency cap: a wedged chain holds its slot
/// while the others pass it, so two wedged members 64 places apart still
/// share one window.
#[tokio::test(start_paused = true)]
async fn reap_beyond_the_concurrency_cap_still_takes_one_window() {
    let (mut mgr, readiness_tx) = dynamic_members_wedged_64_apart();
    mgr.dynamic_ranges.clear();
    let (removed, mgr) = one_readiness_serving_window(&readiness_tx, WINDOW, async move {
        let removed = mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await;
        (removed, mgr)
    })
    .await;
    assert_eq!(removed, 65);
    assert!(mgr.peers.is_empty());
}

#[derive(Default)]
struct CandidateCounters {
    claim: std::sync::atomic::AtomicU32,
    activate: std::sync::atomic::AtomicU32,
}

/// A collision candidate that keeps running after a purge and answers a
/// promotion claim.
fn promotable_candidate(counters: Arc<CandidateCounters>) -> PeerHandle {
    use std::sync::atomic::Ordering::SeqCst;
    let (commands, mut receiver) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            match command {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. }
                | PeerCommand::UpdateGracefulShutdown { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateRuntimeConfig { reply, .. } => {
                    let _ = reply.send(Ok(false));
                }
                PeerCommand::ClaimCollisionPromotion { reply } => {
                    counters.claim.fetch_add(1, SeqCst);
                    let _ = reply.send(true);
                }
                PeerCommand::ActivateMaxPrefixMetrics { reply, .. } => {
                    counters.activate.fetch_add(1, SeqCst);
                    let _ = reply.send(());
                }
                PeerCommand::CollisionDump | PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

/// Two changed peers whose discard list changes, each with a collision
/// candidate: A's purge is admitted, and its primary answers it with
/// `BackToIdle`; C's primary is wedged, so C's purge fails and its candidate
/// is retired. Retiring C's candidate must not handle A's purge-driven
/// `BackToIdle` while A is still installed: that would treat A's primary as
/// failed and promote A's candidate in the middle of A's reconfiguration.
#[tokio::test(start_paused = true)]
async fn a_failed_purge_does_not_promote_another_purged_peers_candidate() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut mgr = test_peer_manager();
    let a = IpAddr::V4(Ipv4Addr::new(127, 0, 4, 1));
    let c = IpAddr::V4(Ipv4Addr::new(127, 0, 4, 2));
    let notify_tx = mgr.session_notify_tx.clone();
    let a_primary = purge_back_to_idle_peer_handle(
        a,
        1,
        rustbgpd_transport::SessionRole::Primary,
        notify_tx,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, a, a_primary, false);
    assert_eq!(mgr.peers[&key(a)].session_id(), 1);
    insert_test_managed_peer(&mut mgr, c, wedged_session(), false);
    let a_candidate = Arc::new(CandidateCounters::default());
    attach_test_pending_inbound(&mut mgr, a, promotable_candidate(a_candidate.clone()), 101);
    attach_test_pending_inbound(
        &mut mgr,
        c,
        promotable_candidate(Arc::new(CandidateCounters::default())),
        102,
    );
    let changed: Vec<_> = [a, c]
        .into_iter()
        .map(|addr| {
            let mut config = make_config(addr, 65002);
            config.discard_path_attributes = std::sync::Arc::from([16_u8]);
            config
        })
        .collect();
    let outcome = mgr.reconcile_peers(Vec::new(), Vec::new(), changed).await;
    assert_eq!(
        outcome.effects,
        vec![PeerReconcileEffect::Replaced(key(a))],
        "{:?}",
        outcome.failures
    );
    assert_eq!(
        a_candidate.claim.load(SeqCst) + a_candidate.activate.load(SeqCst),
        0,
        "a purged peer under reconfiguration must not have its candidate promoted"
    );
}
