//! Sweeps over many peers send their session commands concurrently, under one
//! command window, while serving readiness.
//!
//! A session parked on a full RIB mailbox (ADR-0078) stops draining its
//! command channel, so every bounded command to it costs the whole deadline.
//! Each test wedges every session that way and requires the sweep to end one
//! window after it starts, not one window per peer, with a readiness probe
//! answered inside the 200 ms readiness deadline meanwhile.

use super::*;
use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, PeerReconcileEffect};
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

/// Run `sweep` with a readiness probe already queued. The probe must be
/// answered before `window` ends, while every command still waits; the sweep
/// must still be running 1 ms before one `window` ends and finished when it
/// does. A sequential sweep takes one window per wedged peer, and one that
/// does not serve readiness leaves the probe waiting for all of them.
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
    let probe = window * 3 / 10;
    tokio::time::advance(probe).await;
    settle().await;
    assert!(
        response.try_recv().is_ok(),
        "readiness must be answered while the sweep waits on wedged sessions"
    );
    tokio::time::advance(window.saturating_sub(probe + Duration::from_millis(1))).await;
    settle().await;
    assert!(
        !sweep.is_finished(),
        "the sweep waits for the wedged sessions' command window"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    settle().await;
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
/// refreshes every acknowledging peer with one RIB command.
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
            match update {
                RibUpdate::RefreshPeerOutbound { peer, reply } => {
                    recorded.lock().unwrap().push(vec![peer]);
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::RefreshPeersOutbound { peers, reply } => {
                    recorded.lock().unwrap().push(peers);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
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
    assert_eq!(
        refreshed.len(),
        1,
        "one RIB refresh covers every peer that acknowledged its toggle: {refreshed:?}"
    );
    assert_eq!(
        refreshed[0].iter().copied().collect::<HashSet<_>>(),
        healthy
            .iter()
            .map(|&addr| mgr.rib_peer_of(&key(addr)))
            .collect::<HashSet<_>>(),
    );
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
