//! A resolved policy snapshot's walk serves BFD, link and session events at
//! its seams, holds what would remove a captured peer, and leaves everything
//! else behind it.
//!
//! Each test drives the walk against a RIB stub that holds a reply until it
//! has injected an event or checked one was served, so the order is a
//! handshake: the walk cannot pass a command the stub has not answered.

use super::session_crash::accept_and_establish;
use super::*;

use rustbgpd_api::peer_types::ResolvedPeerPolicy;
use rustbgpd_rib::{PeerExportPolicyRestoreReceipt, RibCommandError};
use rustbgpd_transport::{PeerCommand, SessionIdentity, SessionRole, SessionTaskExitNotice};

use crate::bfd_runtime::BfdStateChangeSender;
use crate::peer_manager::policy::PolicySnapshotFailureKind;

#[derive(Default)]
struct SessionCounters {
    bfd_downs: AtomicU32,
    starts: AtomicU32,
    link_checks: AtomicU32,
    exports: AtomicU32,
    /// Runs once, when the session installs its first export-policy update
    /// and before it acknowledges it.
    on_export: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// Sets its flag when dropped. Declared before a task's exit notice, it
/// drops after it: the flag proves the notice is on the channel.
struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// An Established session that acknowledges policy updates and Route
/// Refreshes and counts the lifecycle commands a served event sends. With
/// `crash`, its task panics when the sender fires and reports its exit as a
/// real session task does; the flag is set once that notice is queued.
fn walk_session(
    addr: IpAddr,
    counters: Arc<SessionCounters>,
    crash: Option<(
        SessionTaskExitNotice,
        oneshot::Receiver<()>,
        Arc<AtomicBool>,
    )>,
) -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel::<PeerCommand>(16);
    let task = tokio::spawn(async move {
        let (exit, mut crashed, exited) = match crash {
            Some((exit, crashed, exited)) => (Some(exit), Some(crashed), Some(exited)),
            None => (None, None, None),
        };
        let _exited = exited.map(SetOnDrop);
        let _exit = exit;
        loop {
            let command = tokio::select! {
                command = command_rx.recv() => command,
                _ = async { crashed.as_mut().unwrap().await }, if crashed.is_some() => {
                    panic!("injected session panic")
                }
            };
            match command {
                Some(PeerCommand::UpdateExportPolicy { reply, .. }) => {
                    counters.exports.fetch_add(1, Ordering::SeqCst);
                    if let Some(hook) = counters.on_export.lock().unwrap().take() {
                        hook();
                    }
                    let _ = reply.send(Ok(()));
                }
                Some(
                    PeerCommand::UpdateImportPolicy { reply, .. }
                    | PeerCommand::SendRouteRefresh { reply, .. },
                ) => {
                    let _ = reply.send(Ok(()));
                }
                Some(PeerCommand::QueryState { reply }) => {
                    let mut state = policy_test_peer_state(addr, SessionState::Established);
                    state.negotiated_session = Some(test_negotiated_session(true));
                    let _ = reply.send(state);
                }
                Some(PeerCommand::BfdDown) => {
                    counters.bfd_downs.fetch_add(1, Ordering::SeqCst);
                }
                Some(PeerCommand::Start) => {
                    counters.starts.fetch_add(1, Ordering::SeqCst);
                }
                Some(PeerCommand::CheckLinks) => {
                    counters.link_checks.fetch_add(1, Ordering::SeqCst);
                }
                Some(PeerCommand::Shutdown | PeerCommand::Stop { .. }) | None => break,
                Some(_) => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

struct Lab {
    mgr: PeerManager,
    rib_rx: mpsc::Receiver<RibUpdate>,
    command_tx: mpsc::Sender<PeerManagerCommand>,
    peers: Vec<IpAddr>,
    sessions: Vec<Arc<SessionCounters>>,
}

/// A manager with `count` static Established peers (10.42.0.1 onward) and
/// the RIB's receiving end.
fn lab(count: u8) -> Lab {
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (command_tx, command_rx) = mpsc::channel(16);
    let mut mgr = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut peers = Vec::new();
    let mut sessions = Vec::new();
    for last in 1..=count {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 42, 0, last));
        let counters = Arc::new(SessionCounters::default());
        insert_test_managed_peer(
            &mut mgr,
            addr,
            walk_session(addr, Arc::clone(&counters), None),
            false,
        );
        peers.push(addr);
        sessions.push(counters);
    }
    mgr.next_session_id = 100;
    Lab {
        mgr,
        rib_rx,
        command_tx,
        peers,
        sessions,
    }
}

/// Couple non-strict BFD to `peer` and return the BFD actor's sender.
fn couple_bfd(mgr: PeerManager, peer: IpAddr) -> (PeerManager, BfdStateChangeSender) {
    let configured = HashMap::from([(peer, super::bfd::bfd_params(peer, false))]);
    let (desired_tx, _desired_rx) = watch::channel(crate::bfd_runtime::BfdRuntimeConfig::default());
    let (states, states_rx) = crate::bfd_runtime::state_change_channel();
    (
        mgr.with_bfd_coupling(desired_tx, states_rx, configured),
        states,
    )
}

/// Mark BFD as owned by a reload generation, as `prepare_bfd_reload` does.
fn begin_generation(mgr: &mut PeerManager) {
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.prior_held.clone_from(&coupling.held_down);
    coupling.pending = Some(coupling.configured.clone());
    coupling.reloading = true;
}

/// One target per peer, each moving to an export chain of its own: no
/// cohort, and every RIB step is a batch of one.
fn distinct_targets(peers: &[IpAddr]) -> Vec<ResolvedPeerPolicy> {
    peers
        .iter()
        .enumerate()
        .map(|(index, address)| ResolvedPeerPolicy {
            address: *address,
            interface: None,
            import_policy: None,
            export_policy: Some(distinct_deny_policy_chain(index)),
        })
        .collect()
}

/// Whether `update` is one of the walk's own RIB commands.
fn is_walk_command(update: &RibUpdate) -> bool {
    matches!(
        update,
        RibUpdate::ReplacePeerExportPoliciesAuthoritatively { .. }
            | RibUpdate::ReplacePeerExportPolicies { .. }
            | RibUpdate::RestorePeerExportPoliciesAuthoritatively { .. }
    )
}

/// Acknowledge one of the walk's RIB commands as applied.
fn answer(update: RibUpdate) {
    match update {
        RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. } => {
            let _ = reply.send(Ok(Vec::new()));
        }
        RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
            let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
        }
        RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
            let _ = reply.send(Ok(()));
        }
        RibUpdate::PublishDampeningOwners { reply, .. } => {
            let _ = reply.send(Ok(()));
        }
        RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } => {
            let _ = reply.send(Ok(replacements
                .iter()
                .rev()
                .map(|replacement| PeerExportPolicyRestoreReceipt::Restored {
                    peer: replacement.peer,
                })
                .collect()));
        }
        _ => {}
    }
}

/// Whether `counter` reaches `expected` while the caller holds the walk.
async fn reaches(counter: &AtomicU32, expected: u32) -> bool {
    for _ in 0..200 {
        if counter.load(Ordering::SeqCst) >= expected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

async fn set(flag: &AtomicBool) {
    for _ in 0..1000 {
        if flag.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the awaited step never happened");
}

/// E-1, RPC path and inside a generation: a BFD Down that arrives during
/// one unit stops its BGP session at the seam after that unit, before the
/// walk's next RIB command. Inside a generation the hold is also a prior
/// one, so it outlives the generation's abort.
///
/// LOAD-BEARING: a walk that serves no events delivers `BfdDown` only after
/// it has ended, and inside a generation never.
#[tokio::test(start_paused = true)]
async fn bfd_down_mid_walk_reaches_its_session_before_the_next_rib_command() {
    for in_generation in [false, true] {
        let Lab {
            mgr,
            mut rib_rx,
            peers,
            sessions,
            ..
        } = lab(3);
        let (mut mgr, states) = couple_bfd(mgr, peers[2]);
        if in_generation {
            begin_generation(&mut mgr);
        }
        let held = Arc::clone(&sessions[2]);
        let peer = peers[2];
        let rib = tokio::spawn(async move {
            let mut commands = 0;
            let mut served_before_next = None;
            while let Some(update) = rib_rx.recv().await {
                if is_walk_command(&update) {
                    commands += 1;
                    match commands {
                        1 => states.send(down(peer)),
                        2 => served_before_next = Some(reaches(&held.bfd_downs, 1).await),
                        _ => {}
                    }
                }
                answer(update);
            }
            (commands, served_before_next)
        });
        let result = mgr
            .apply_resolved_policy_snapshot(distinct_targets(&peers))
            .await;
        assert!(result.is_ok(), "{in_generation}: {result:?}");
        assert!(mgr.bfd_withholding(&peer), "{in_generation}");
        if in_generation {
            mgr.abort_bfd_reload();
            assert!(
                mgr.bfd_withholding(&peer),
                "an aborted generation keeps the hold a real Down took"
            );
        }
        drop(mgr);
        assert_eq!(
            rib.await.unwrap(),
            (3, Some(true)),
            "in_generation={in_generation}"
        );
        assert_eq!(sessions[2].bfd_downs.load(Ordering::SeqCst), 1);
        assert_eq!(sessions[2].starts.load(Ordering::SeqCst), 0);
    }
}

/// A `BfdDown` that met a full session mailbox before the walk is retried at
/// the walk's seams, in and out of a generation; a `Start` retry inside a
/// generation waits for it to end.
///
/// LOAD-BEARING: the run loop's retry timer is not polled during a walk and
/// reports no deadline at all while a generation holds BFD.
#[tokio::test(start_paused = true)]
async fn due_bfd_down_retry_is_delivered_at_a_walk_seam() {
    for (in_generation, start) in [(false, false), (true, false), (true, true)] {
        let Lab {
            mgr,
            mut rib_rx,
            peers,
            sessions,
            ..
        } = lab(3);
        let (mut mgr, _states) = couple_bfd(mgr, peers[2]);
        mgr.mark_bfd_withheld(peers[2]);
        mgr.schedule_bfd_retry(peers[2], start);
        if in_generation {
            begin_generation(&mut mgr);
        }
        let retried = Arc::clone(&sessions[2]);
        let rib = tokio::spawn(async move {
            let mut commands = 0;
            let mut delivered = None;
            while let Some(update) = rib_rx.recv().await {
                if is_walk_command(&update) {
                    commands += 1;
                    match commands {
                        // Past the retry's 100 ms deadline.
                        1 => tokio::time::sleep(Duration::from_millis(200)).await,
                        2 => {
                            let counter = if start {
                                &retried.starts
                            } else {
                                &retried.bfd_downs
                            };
                            delivered = Some(reaches(counter, 1).await);
                        }
                        _ => {}
                    }
                }
                answer(update);
            }
            delivered
        });
        let result = mgr
            .apply_resolved_policy_snapshot(distinct_targets(&peers))
            .await;
        assert!(result.is_ok(), "{result:?}");
        drop(mgr);
        assert_eq!(
            rib.await.unwrap(),
            Some(!start),
            "in_generation={in_generation} start={start}"
        );
    }
}

/// A link change is served while the walk waits for a RIB reply, not only
/// at the seam after it: fast external failover does not wait for a unit.
///
/// LOAD-BEARING: the plain readiness wait has no link arm, so the check is
/// dispatched only once the reply has arrived.
#[tokio::test(start_paused = true)]
async fn link_change_is_served_while_the_walk_waits_for_the_rib() {
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        sessions,
        ..
    } = lab(2);
    let (links, link_rx) = watch::channel(Arc::new(rustbgpd_transport::LinkSnapshot::default()));
    mgr = mgr.with_link_failover(link_rx);
    for peer in &peers {
        mgr.peers
            .get_mut(&key(*peer))
            .unwrap()
            .transport_config
            .fast_external_failover = true;
    }
    let checked = Arc::clone(&sessions[0]);
    let rib = tokio::spawn(async move {
        let mut during_wait = None;
        while let Some(update) = rib_rx.recv().await {
            if is_walk_command(&update) && during_wait.is_none() {
                links
                    .send(Arc::new(rustbgpd_transport::LinkSnapshot::default()))
                    .unwrap();
                during_wait = Some(reaches(&checked.link_checks, 1).await);
            }
            answer(update);
        }
        during_wait
    });
    let result = mgr
        .apply_resolved_policy_snapshot(distinct_targets(&peers))
        .await;
    assert!(result.is_ok(), "{result:?}");
    drop(mgr);
    assert_eq!(rib.await.unwrap(), Some(true));
}

/// E-4: a notification that would retire a dynamic peer mid-walk is held.
/// The walk's later failure restores the peer exactly, and the peer is
/// retired once the walk has ended, from the notification the walk put back.
///
/// LOAD-BEARING: retiring it at the seam removes a captured peer, so the
/// rollback reports `policy_rollback_peer_gone` and is ambiguous.
#[tokio::test(start_paused = true)]
async fn dynamic_idle_mid_walk_is_held_until_the_walk_has_rolled_back() {
    for task_exited in [false, true] {
        let Lab {
            mut mgr,
            mut rib_rx,
            peers,
            ..
        } = lab(1);
        let dynamic = IpAddr::V4(Ipv4Addr::new(10, 42, 9, 1));
        let dynamic_session = 50;
        insert_test_dynamic_managed_peer(
            &mut mgr,
            dynamic,
            dynamic_session,
            walk_session(dynamic, Arc::default(), None),
            true,
            IpAddr::V4(Ipv4Addr::new(10, 42, 9, 0)),
            24,
            "dynamic",
        );
        let notices = mgr.session_notify_tx.clone();
        let rib = tokio::spawn(async move {
            let mut commands = 0;
            while let Some(update) = rib_rx.recv().await {
                if !is_walk_command(&update) {
                    continue;
                }
                commands += 1;
                match (commands, update) {
                    // The dynamic peer's own batch: it is captured and
                    // applied when its session reports Idle (or its task
                    // ends).
                    (1, update) => {
                        let notice = if task_exited {
                            SessionNotification::TaskExited {
                                session_id: dynamic_session,
                                role: SessionRole::Primary,
                                peer_addr: dynamic,
                                cause: "ended".into(),
                            }
                        } else {
                            SessionNotification::BackToIdle {
                                session_id: dynamic_session,
                                role: SessionRole::Primary,
                                peer_addr: dynamic,
                            }
                        };
                        notices.send(notice).unwrap();
                        answer(update);
                    }
                    (2, RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. }) => {
                        let _ = reply.send(Err(RibCommandError::internal("refused")));
                    }
                    (_, update) => answer(update),
                }
            }
        });
        let failure = mgr
            .apply_resolved_policy_snapshot_classified(distinct_targets(&[dynamic, peers[0]]), true)
            .await
            .expect_err("the second batch is refused");
        assert_eq!(
            failure.kind,
            PolicySnapshotFailureKind::FullyCompensated,
            "task_exited={task_exited}: {} ({})",
            failure.message(),
            failure.code.as_str()
        );
        assert!(
            mgr.peers.contains_key(&key(dynamic)),
            "the walk does not retire a peer it captured"
        );
        assert_eq!(mgr.peers[&key(dynamic)].export_policy, None);

        let held = mgr
            .session_notify_rx
            .try_recv()
            .expect("the held notification is back on the channel");
        mgr.handle_session_notification(held).await;
        assert!(
            !mgr.peers.contains_key(&key(dynamic)),
            "task_exited={task_exited}: retired after the walk"
        );
        drop(mgr);
        rib.await.unwrap();
    }
}

/// E-4, a real task exit: a dynamic peer's session task ends mid-walk and
/// its retirement is held, so the peer stays in the table with no session.
/// The walk treats it as a known-down peer: it carries the chains and owes
/// no session step. A later failure restores every peer exactly; a walk
/// that reaches the peer after its task ended commits. Neither waits out a
/// session deadline, and the peer is retired once the walk has ended.
///
/// LOAD-BEARING: a session step sent to the ended task fails, so the
/// forward walk rolls back and the rollback, which cannot reassert the
/// prior chain either, is ambiguous.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one test holds the crashing session, the scripted RIB and both outcomes"
)]
async fn dynamic_task_exit_mid_walk_owes_no_session_step() {
    for fail_later in [true, false] {
        let Lab {
            mut mgr,
            mut rib_rx,
            peers,
            ..
        } = lab(2);
        let dynamic = IpAddr::V4(Ipv4Addr::new(10, 42, 9, 1));
        let dynamic_session = 50;
        let (crash, crashed) = oneshot::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let exit = SessionTaskExitNotice::new(
            Some(mgr.session_notify_tx.clone()),
            SessionIdentity::primary(dynamic_session),
            dynamic,
        );
        insert_test_dynamic_managed_peer(
            &mut mgr,
            dynamic,
            dynamic_session,
            walk_session(
                dynamic,
                Arc::default(),
                Some((exit, crashed, Arc::clone(&exited))),
            ),
            true,
            IpAddr::V4(Ipv4Addr::new(10, 42, 9, 0)),
            24,
            "dynamic",
        );
        // Rollback: the dynamic peer's unit commits, its task ends during
        // the second unit and the third is refused. Forward: its task ends
        // during the first unit, before the walk reaches it.
        let (order, crash_at, refuse_at) = if fail_later {
            ([dynamic, peers[0], peers[1]], 2, 3)
        } else {
            ([peers[0], dynamic, peers[1]], 1, 0)
        };
        let rib = tokio::spawn(async move {
            let mut commands = 0;
            let mut crash = Some(crash);
            while let Some(update) = rib_rx.recv().await {
                if !is_walk_command(&update) {
                    answer(update);
                    continue;
                }
                commands += 1;
                if commands == crash_at {
                    // The exit notice is queued before the unit's reply.
                    crash.take().unwrap().send(()).unwrap();
                    set(&exited).await;
                }
                match update {
                    RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. }
                        if commands == refuse_at =>
                    {
                        let _ = reply.send(Err(RibCommandError::internal("refused")));
                    }
                    update => answer(update),
                }
            }
        });
        let targets = distinct_targets(&order);
        let candidate = targets
            .iter()
            .find(|target| target.address == dynamic)
            .unwrap()
            .export_policy
            .clone();
        let started = tokio::time::Instant::now();
        let result = mgr
            .apply_resolved_policy_snapshot_classified(targets, true)
            .await;
        assert!(
            started.elapsed() < PEER_POLICY_UPDATE_TIMEOUT,
            "fail_later={fail_later}: the walk waited {:?} on the ended session",
            started.elapsed()
        );
        let expected = if fail_later {
            let failure = result.expect_err("the third batch is refused");
            assert_eq!(
                failure.kind,
                PolicySnapshotFailureKind::FullyCompensated,
                "{} ({})",
                failure.message(),
                failure.code.as_str()
            );
            None
        } else {
            assert!(
                result.is_ok(),
                "{:?}",
                result.err().map(|failure| failure.message().to_owned())
            );
            candidate
        };
        assert_eq!(
            mgr.peers[&key(dynamic)].export_policy,
            expected,
            "fail_later={fail_later}: the walk does not retire a peer it captured"
        );

        let held = mgr
            .session_notify_rx
            .try_recv()
            .expect("the held notification is back on the channel");
        mgr.handle_session_notification(held).await;
        assert!(
            !mgr.peers.contains_key(&key(dynamic)),
            "fail_later={fail_later}: retired after the walk"
        );
        drop(mgr);
        rib.await.unwrap();
    }
}

/// E-5, flood: a seam serves at most the per-kind budget of session
/// notifications, the rest stay queued, and the walk commits.
///
/// LOAD-BEARING: an unbounded round drains the whole queue at one seam.
#[tokio::test(start_paused = true)]
async fn a_notification_flood_costs_one_seam_its_budget() {
    const FLOOD: usize = 50;
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(3);
    let notices = mgr.session_notify_tx.clone();
    let session_id = mgr.peers[&key(peers[0])].session_id();
    let flooded = peers[0];
    let rib = tokio::spawn(async move {
        let mut commands = 0;
        while let Some(update) = rib_rx.recv().await {
            if is_walk_command(&update) {
                commands += 1;
                // The last forward command. Two seams follow it: after
                // the batch's reply and at the end of its unit.
                if commands == 3 {
                    for _ in 0..FLOOD {
                        notices
                            .send(SessionNotification::BackToIdle {
                                session_id,
                                role: SessionRole::Primary,
                                peer_addr: flooded,
                            })
                            .unwrap();
                    }
                }
            }
            answer(update);
        }
    });
    let result = mgr
        .apply_resolved_policy_snapshot(distinct_targets(&peers))
        .await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        mgr.session_notify_rx.ready_count(),
        FLOOD - 2 * OWNED_WALK_EVENT_BUDGET,
        "each seam serves its budget and no more"
    );
    drop(mgr);
    rib.await.unwrap();
}

/// E-5, the documented exception to the budget: a seam whose round retires
/// a session handles every notification queued at that moment, and counts
/// each one. A pending inbound candidate's Idle ahead of a flood leaves
/// nothing queued after one seam.
///
/// LOAD-BEARING: `events_served` counted from the budget reports eight.
#[tokio::test(start_paused = true)]
async fn a_retiring_round_at_a_seam_handles_the_whole_queue() {
    const FLOOD: usize = 50;
    let Lab { mut mgr, peers, .. } = lab(2);
    let candidate = 60;
    attach_test_pending_inbound(
        &mut mgr,
        peers[1],
        walk_session(peers[1], Arc::default(), None),
        candidate,
    );
    mgr.session_notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: candidate,
            role: SessionRole::InboundCandidate,
            peer_addr: peers[1],
        })
        .unwrap();
    let session_id = mgr.peers[&key(peers[0])].session_id();
    for _ in 0..FLOOD {
        mgr.session_notify_tx
            .send(SessionNotification::BackToIdle {
                session_id,
                role: SessionRole::Primary,
                peer_addr: peers[0],
            })
            .unwrap();
    }
    let service = serve_one_seam(&mut mgr).await;
    assert_eq!(
        mgr.session_notify_rx.ready_count(),
        0,
        "nothing left queued"
    );
    assert!(mgr.peers[&key(peers[1])].pending_inbound.is_none());
    assert_eq!(
        service.events_served,
        u64::try_from(FLOOD + 1).unwrap(),
        "every handled notification is counted"
    );
}

/// One seam of a walk that owns the actor, and what it served.
async fn serve_one_seam(mgr: &mut PeerManager) -> OwnedWalkService {
    assert!(mgr.begin_owned_walk());
    mgr.serve_owned_walk_events().await;
    mgr.end_owned_walk()
}

/// A static neighbor's max-prefix breach is served at a seam: the session
/// is stopped and the neighbor latched.
///
/// LOAD-BEARING: a seam that serves no session notification leaves the
/// breached session running until the walk ends.
#[tokio::test]
async fn max_prefix_breach_is_latched_at_a_seam() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 34));
    let primary = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Established, None, primary.clone()),
        false,
    );
    let session_id = mgr.peers[&key(addr)].session_id();
    mgr.session_notify_tx
        .send(SessionNotification::MaxPrefixExceeded {
            session_id,
            role: SessionRole::Primary,
            peer_addr: addr,
            count: 501,
            bound: 500,
            family: None,
            received: false,
            path_limit: false,
        })
        .unwrap();
    serve_one_seam(&mut mgr).await;
    assert!(!mgr.peers[&key(addr)].enabled);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
    wait_counter(&primary.stop, 1).await;
}

/// A static neighbor's crash that reaches the latch is served at a seam:
/// the neighbor is latched disabled instead of restarted.
///
/// LOAD-BEARING: a seam that serves no session notification leaves the
/// crash unhandled until the walk ends.
#[tokio::test(start_paused = true)]
async fn crash_latch_is_applied_at_a_seam() {
    use super::session_crash::{
        SESSION_CRASH_LATCH, crash_primary, install_crashing_primary, manager_with_peer,
    };
    let peer = key(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut mgr = manager_with_peer();
    for _ in 1..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &peer);
        crash_primary(&mut mgr, trigger).await;
        tokio::time::advance(Duration::from_secs(60)).await;
    }
    install_crashing_primary(&mut mgr, &peer).send(()).unwrap();
    for _ in 0..100 {
        if mgr.session_notify_rx.ready_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(mgr.session_notify_rx.ready_count(), 1, "the exit notice");
    serve_one_seam(&mut mgr).await;
    assert!(mgr.session_crash_latched(&peer));
    assert!(!mgr.peers[&peer].enabled);
}

/// An OPEN collision is resolved at a seam: the local side wins and the
/// inbound candidate is dropped.
///
/// LOAD-BEARING: a seam that serves no session notification leaves the
/// candidate pending until the walk ends.
#[tokio::test]
async fn open_collision_is_resolved_at_a_seam() {
    let (_command_tx, command_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 10),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let router_id = Some(Ipv4Addr::new(10, 0, 0, 2));
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        addr,
        65002,
        fake_peer_handle(addr, SessionState::OpenConfirm, router_id, Arc::default()),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::OpenConfirm, router_id, pending.clone()),
        2,
    );
    mgr.session_notify_tx
        .send(SessionNotification::OpenReceived {
            session_id: 2,
            role: SessionRole::InboundCandidate,
            peer_addr: addr,
            remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_asn: 65002,
        })
        .unwrap();
    serve_one_seam(&mut mgr).await;
    wait_counter(&pending.collision_dump, 1).await;
    assert!(
        mgr.peers[&key(addr)].pending_inbound.is_none(),
        "the local side keeps its session"
    );
}

/// E-5, stall: events that keep arriving while a unit never completes do
/// not keep the walk alive. It rolls back one stall timeout after its last
/// completed RIB command, plus only the time the seam after that command
/// spent serving, which is not the RIB's.
///
/// The first peer's batch hands it back for the paced walk, so the seam
/// after the batch is followed directly by the paced command that stalls.
/// The seam's service takes `PEER_LIFECYCLE_COMMAND_TIMEOUT`: the BFD Down
/// it serves stops a pending inbound candidate that never exits.
///
/// LOAD-BEARING: charging the service time to the stall budget ends the
/// walk that much early.
///
/// This test pins that service time is excluded, not that serving never
/// renews the stall timer, and no forward walk can tell the two apart.
/// Every seam of the per-peer, batch and paced walks directly follows a
/// completed unit's `progressed()`, with no time between them but the
/// service the seam excludes, so a renewal at the seam lands where that one
/// did. A cohort's seams precede the remainder walk, whose first session
/// step renews the timer before its first RIB command. A renewal at a seam
/// is visible only in a later rollback partition (the cohort's restore
/// after the remainder's) whose session restores take time; no test drives
/// that shape.
#[tokio::test(start_paused = true)]
async fn events_do_not_renew_a_stalled_walk() {
    let first_command = Duration::from_secs(80);
    let Lab {
        mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(3);
    let (mut mgr, states) = couple_bfd(mgr, peers[2]);
    attach_test_pending_inbound(
        &mut mgr,
        peers[2],
        stalled_shutdown_peer_handle(Arc::default()).await,
        60,
    );
    let notices = mgr.session_notify_tx.clone();
    let session_id = mgr.peers[&key(peers[0])].session_id();
    let (flooded, held) = (peers[0], peers[2]);
    let arriving = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if notices
                .send(SessionNotification::BackToIdle {
                    session_id,
                    role: SessionRole::Primary,
                    peer_addr: flooded,
                })
                .is_err()
            {
                return;
            }
        }
    });
    let rib = tokio::spawn(async move {
        let mut commands = 0;
        let mut stalled = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    commands += 1;
                    tokio::time::sleep(first_command).await;
                    states.send(down(held));
                    let _ = reply.send(Ok(vec![replacements[0].peer]));
                }
                RibUpdate::ApplyPacedExportPolicies { reply, .. } => {
                    commands += 1;
                    stalled.push(reply);
                }
                update => answer(update),
            }
        }
        commands
    });
    let started = tokio::time::Instant::now();
    let result = mgr
        .apply_resolved_policy_snapshot(distinct_targets(&peers))
        .await;
    let elapsed = started.elapsed();
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("already-applied peers restored") && !error.contains("also failed")
        }),
        "{result:?}"
    );
    assert_eq!(
        elapsed,
        first_command + PEER_LIFECYCLE_COMMAND_TIMEOUT + RIB_BATCH_REPLY_TIMEOUT
    );
    assert!(mgr.bfd_withholding(&held));
    drop(mgr);
    arriving.await.unwrap();
    assert_eq!(rib.await.unwrap(), 2, "no command follows the stalled one");
}

/// E-5, the command lane: a peer add, an inbound connection and `Shutdown`
/// queued during a walk are dispatched only after it, in order, while a BFD
/// Down queued beside them is served at the walk's next seam.
#[tokio::test]
async fn commands_queued_mid_walk_wait_for_it_while_events_are_served() {
    let Lab {
        mgr,
        mut rib_rx,
        command_tx,
        peers,
        sessions,
    } = lab(2);
    let (mgr, states) = couple_bfd(mgr, peers[1]);
    let (first_command_tx, first_command) = oneshot::channel();
    let (release_tx, release) = oneshot::channel::<()>();
    let (second_command_tx, second_command) = oneshot::channel();
    let (finish_tx, finish) = oneshot::channel::<()>();
    let rib = tokio::spawn(async move {
        let mut gates = Some((first_command_tx, release, second_command_tx, finish));
        let mut commands = 0;
        while let Some(update) = rib_rx.recv().await {
            if is_walk_command(&update) {
                commands += 1;
                if commands == 1 {
                    let (first, release, second, finish) = gates.take().unwrap();
                    first.send(()).unwrap();
                    release.await.unwrap();
                    answer(update);
                    // The second command is held until the test has looked.
                    let held = loop {
                        let update = rib_rx.recv().await.unwrap();
                        if is_walk_command(&update) {
                            break update;
                        }
                    };
                    second.send(()).unwrap();
                    finish.await.unwrap();
                    answer(held);
                    continue;
                }
            }
            answer(update);
        }
    });
    let manager = tokio::spawn(mgr.run());

    let (walk_reply, mut walked) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: distinct_targets(&peers),
            reply: walk_reply,
        })
        .await
        .unwrap();
    first_command.await.unwrap();

    // Queued behind the walk: a peer add, an inbound connection, Shutdown.
    let (add_reply, mut added) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::AddPeer {
            config: make_config(IpAddr::V4(Ipv4Addr::new(10, 42, 7, 1)), 65077),
            sync_config_snapshot: false,
            reply: add_reply,
        })
        .await
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, peer_addr) = listener.accept().await.unwrap();
    command_tx
        .send(PeerManagerCommand::AcceptInbound {
            stream,
            peer_addr,
            tcp_ao_info: None,
            tcp_ao_generation: None,
        })
        .await
        .unwrap();
    command_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    states.send(down(peers[1]));
    release_tx.send(()).unwrap();

    // The walk is now held at its second command.
    second_command.await.unwrap();
    assert!(
        reaches(&sessions[1].bfd_downs, 1).await,
        "the BFD Down is served at the seam before the second command"
    );
    assert!(walked.try_recv().is_err(), "the walk is still running");
    assert!(added.try_recv().is_err(), "the peer add waits for the walk");
    assert!(
        client.try_read(&mut [0_u8; 1]).is_err(),
        "the inbound connection waits for the walk"
    );
    assert!(!manager.is_finished(), "Shutdown waits for the walk");

    finish_tx.send(()).unwrap();
    assert!(walked.await.unwrap().is_ok());
    assert!(added.await.unwrap().is_ok());
    // No neighbor is configured at the connection's address: it is closed.
    assert!(matches!(client.read(&mut [0_u8; 1]).await, Ok(0) | Err(_)));
    manager.await.unwrap();
    rib.await.unwrap();
}

/// E-5, cohort setup: events served between two members of a cohort's
/// session setup leave every member in the peer table. A dynamic member's
/// Idle is held, a static member's BFD Down is served, and the cohort
/// commits.
///
/// LOAD-BEARING: retiring the dynamic member at the seam panics the setup
/// loop's `expect("cohort peer existed ...")`.
#[tokio::test(start_paused = true)]
async fn events_between_cohort_setup_members_keep_every_member() {
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        sessions,
        ..
    } = lab(2);
    let dynamic = IpAddr::V4(Ipv4Addr::new(10, 42, 9, 1));
    let dynamic_session = 50;
    insert_test_dynamic_managed_peer(
        &mut mgr,
        dynamic,
        dynamic_session,
        walk_session(dynamic, Arc::default(), None),
        true,
        IpAddr::V4(Ipv4Addr::new(10, 42, 9, 0)),
        24,
        "dynamic",
    );
    let (mut mgr, states) = couple_bfd(mgr, peers[1]);
    let notices = mgr.session_notify_tx.clone();
    let held = peers[1];
    // Between the first member's setup and the second's.
    *sessions[0].on_export.lock().unwrap() = Some(Box::new(move || {
        notices
            .send(SessionNotification::BackToIdle {
                session_id: dynamic_session,
                role: SessionRole::Primary,
                peer_addr: dynamic,
            })
            .unwrap();
        states.send(down(held));
    }));
    let stopped = Arc::clone(&sessions[1]);
    let rib = tokio::spawn(async move {
        let mut served_before_transition = None;
        while let Some(update) = rib_rx.recv().await {
            if matches!(update, RibUpdate::ReplacePeerExportPolicies { .. }) {
                served_before_transition = Some(reaches(&stopped.bfd_downs, 1).await);
            }
            answer(update);
        }
        served_before_transition
    });
    // One shared export move: a cohort of three, the dynamic member second.
    let chain = Some(deny_policy_chain());
    let targets = [peers[0], dynamic, peers[1]]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: chain.clone(),
        })
        .collect();
    let result = mgr.apply_resolved_policy_snapshot(targets).await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(mgr.peers[&key(dynamic)].export_policy, chain);
    assert_eq!(mgr.session_notify_rx.ready_count(), 1, "the held Idle");
    drop(mgr);
    assert_eq!(rib.await.unwrap(), Some(true));
}

/// E-4 in a cohort: a dynamic member's session task ends and the walk holds
/// its retirement. The cohort treats the member as the per-peer walk does:
/// it carries the chains and owes no session step and no Route Refresh. A
/// task that ends after its setup step, followed by a refused transition,
/// is restored exactly; a walk that reaches the member after its task ended
/// commits, with or without an import change.
///
/// LOAD-BEARING: the cohort's session steps go to the ended task, so the
/// setup (or the deferred refresh) fails and the walk rolls back.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one test holds the crashing session, the scripted RIB and every outcome"
)]
async fn dynamic_cohort_member_task_exit_owes_no_session_step() {
    for (fail_later, import_changes) in [(true, false), (false, false), (false, true)] {
        let Lab {
            mut mgr,
            mut rib_rx,
            peers,
            ..
        } = lab(2);
        let dynamic = IpAddr::V4(Ipv4Addr::new(10, 42, 9, 1));
        let dynamic_session = 50;
        let (crash, crashed) = oneshot::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let exit = SessionTaskExitNotice::new(
            Some(mgr.session_notify_tx.clone()),
            SessionIdentity::primary(dynamic_session),
            dynamic,
        );
        insert_test_dynamic_managed_peer(
            &mut mgr,
            dynamic,
            dynamic_session,
            walk_session(
                dynamic,
                Arc::default(),
                Some((exit, crashed, Arc::clone(&exited))),
            ),
            true,
            IpAddr::V4(Ipv4Addr::new(10, 42, 9, 0)),
            24,
            "dynamic",
        );
        // Rollback: the dynamic member is set up first, its task ends during
        // the refused transition, and the restore, newest first, reaches it
        // after a seam. Forward: its task ends during the prestage, and the
        // seam after the first member's setup holds it.
        let order = if fail_later {
            [dynamic, peers[0], peers[1]]
        } else {
            [peers[0], dynamic, peers[1]]
        };
        let rib = tokio::spawn(async move {
            let mut crash = Some(crash);
            while let Some(update) = rib_rx.recv().await {
                let crash_here = match &update {
                    RibUpdate::PrepareExportPolicyDestination { .. } => !fail_later,
                    RibUpdate::ReplacePeerExportPolicies { .. } => fail_later,
                    _ => false,
                };
                if crash_here {
                    // The exit notice is queued before the command's reply.
                    crash.take().unwrap().send(()).unwrap();
                    set(&exited).await;
                }
                match update {
                    RibUpdate::ReplacePeerExportPolicies { reply, .. } if fail_later => {
                        let _ = reply.send(Err("refused".to_string()));
                    }
                    update => answer(update),
                }
            }
        });
        let chain = Some(deny_policy_chain());
        let import = import_changes.then(deny_policy_chain);
        let targets = order
            .into_iter()
            .map(|address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: import.clone(),
                export_policy: chain.clone(),
            })
            .collect();
        let started = tokio::time::Instant::now();
        let result = mgr
            .apply_resolved_policy_snapshot_classified(targets, true)
            .await;
        let variant = format!("fail_later={fail_later} import_changes={import_changes}");
        assert!(
            started.elapsed() < PEER_POLICY_UPDATE_TIMEOUT,
            "{variant}: the walk waited {:?} on the ended session",
            started.elapsed()
        );
        let (export, import) = if fail_later {
            let failure = result.expect_err("the transition is refused");
            assert_eq!(
                failure.kind,
                PolicySnapshotFailureKind::FullyCompensated,
                "{variant}: {} ({})",
                failure.message(),
                failure.code.as_str()
            );
            (None, None)
        } else {
            assert!(
                result.is_ok(),
                "{variant}: {:?}",
                result.err().map(|failure| failure.message().to_owned())
            );
            (chain, import)
        };
        let managed = &mgr.peers[&key(dynamic)];
        assert_eq!(managed.export_policy, export, "{variant}");
        assert_eq!(managed.import_policy, import, "{variant}");
        assert!(
            !managed.pending_refresh,
            "{variant}: the member owes nothing"
        );

        let held = mgr
            .session_notify_rx
            .try_recv()
            .expect("the held notification is back on the channel");
        mgr.handle_session_notification(held).await;
        assert!(
            !mgr.peers.contains_key(&key(dynamic)),
            "{variant}: retired after the walk"
        );
        drop(mgr);
        rib.await.unwrap();
    }
}

/// E-3, rollback: a session task that ends while the walk waits for its
/// detached RIB restore is replaced when the restore next completes a
/// command. The replacement starts on the chain the rollback's session legs
/// had already restored, the restore still accounts for the peer under its
/// unchanged RIB identity, and the rollback is exact.
///
/// LOAD-BEARING: with no seam in the restore wait the dead session is
/// replaced only after the walk.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one test holds the crashing session, the scripted RIB and the re-established session"
)]
async fn session_crash_during_the_rollback_wait_restarts_on_the_restored_chain() {
    let crashing = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(2);
    let (crash, crashed) = oneshot::channel();
    let exited = Arc::new(AtomicBool::new(false));
    let crashing_session = u64::try_from(mgr.peers.len()).unwrap() + 1;
    let exit = SessionTaskExitNotice::new(
        Some(mgr.session_notify_tx.clone()),
        SessionIdentity::primary(crashing_session),
        crashing,
    );
    insert_test_managed_peer(
        &mut mgr,
        crashing,
        walk_session(
            crashing,
            Arc::default(),
            Some((exit, crashed, Arc::clone(&exited))),
        ),
        false,
    );
    assert_eq!(mgr.peers[&key(crashing)].session_id(), crashing_session);
    // Three prior chains, so the restore is three commands, newest first:
    // the crashing peer's is the last.
    let prior = Some(distinct_deny_policy_chain(7));
    mgr.peers.get_mut(&key(peers[0])).unwrap().export_policy = Some(distinct_deny_policy_chain(8));
    {
        let managed = mgr.peers.get_mut(&key(crashing)).unwrap();
        managed.export_policy.clone_from(&prior);
        managed.transport_config.remote_addr = listener.local_addr().unwrap();
    }
    let (readiness, readiness_rx) = mpsc::channel(1);
    mgr = mgr.with_readiness_queries(readiness_rx);
    let (registered_tx, mut registered) = mpsc::unbounded_channel();
    let rib = tokio::spawn(async move {
        let (mut forward, mut restores) = (0, 0);
        let mut crash = Some(crash);
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. } => {
                    forward += 1;
                    let _ = reply.send(if forward < 3 {
                        Ok(Vec::new())
                    } else {
                        Err(RibCommandError::internal("refused"))
                    });
                }
                update @ RibUpdate::RestorePeerExportPoliciesAuthoritatively { .. } => {
                    restores += 1;
                    if let Some(crash) = crash.take() {
                        // The first command is queued, so the walk's next
                        // poll runs straight into its restore wait, past
                        // every seam of the rollback's session steps. Only
                        // that wait answers a readiness probe sent now.
                        let (reply, in_restore_wait) = oneshot::channel();
                        readiness
                            .send(PeerManagerReadinessQuery::Ping { reply })
                            .await
                            .unwrap();
                        in_restore_wait.await.unwrap();
                        crash.send(()).unwrap();
                        set(&exited).await;
                        answer(update);
                        // That command's completion is the seam. Hold the
                        // next one until the walk has replaced the dead
                        // session (its `PeerDown`), or has clearly not.
                        let mut held = Vec::new();
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            loop {
                                match rib_rx.recv().await {
                                    Some(RibUpdate::PeerDown { .. }) | None => return,
                                    Some(update) => held.push(update),
                                }
                            }
                        })
                        .await;
                        restores += held.len();
                        held.into_iter().for_each(answer);
                        continue;
                    }
                    answer(update);
                }
                RibUpdate::PeerUp {
                    session_id,
                    export_policy,
                    ..
                } => {
                    let _ = registered_tx.send((session_id, export_policy));
                }
                _ => {}
            }
        }
        restores
    });

    let failure = mgr
        .apply_resolved_policy_snapshot_classified(
            distinct_targets(&[crashing, peers[0], peers[1]]),
            true,
        )
        .await
        .expect_err("the third batch is refused");
    assert_eq!(
        failure.kind,
        PolicySnapshotFailureKind::FullyCompensated,
        "{} ({})",
        failure.message(),
        failure.code.as_str()
    );
    let restarted = mgr.peers[&key(crashing)].session_id();
    assert_ne!(
        restarted, crashing_session,
        "the dead session was replaced during the walk"
    );
    assert_eq!(mgr.peers[&key(crashing)].export_policy, prior);

    let _client = accept_and_establish(&listener).await;
    let (session_id, export_policy) =
        tokio::time::timeout(Duration::from_secs(5), registered.recv())
            .await
            .expect("the restarted session registers")
            .unwrap();
    assert_eq!(session_id, restarted);
    assert_eq!(export_policy, prior, "it runs the restored chain");
    mgr.delete_peer(key(crashing), false).await.unwrap();
    drop(mgr);
    assert_eq!(rib.await.unwrap(), 3, "one restore command per prior chain");
}

/// A hold a seam took inside a generation meets that generation's commit.
/// A candidate that replaces the member's BFD session (a new revision) keeps
/// the hold, and the new session's Up sends the `Start`; a candidate that
/// removes the member releases the hold at commit. Either way the session
/// that was told `BfdDown` is started exactly once.
#[tokio::test(start_paused = true)]
async fn a_hold_taken_in_a_generation_meets_its_commit() {
    for removed in [false, true] {
        let Lab {
            mgr,
            peers,
            sessions,
            ..
        } = lab(1);
        let peer = peers[0];
        let (mgr, states) = couple_bfd(mgr, peer);
        let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
        let mut mgr = mgr.with_bfd_reload(reload_tx);
        let actor = tokio::spawn(async move {
            while let Some(command) = reload_rx.recv().await {
                // Every desired session re-reports its level: a new one is Down.
                let acks = command
                    .desired
                    .sessions
                    .iter()
                    .map(|params| {
                        let mut ack = down(params.peer);
                        ack.revision = params.revision;
                        ack.resync = true;
                        ack
                    })
                    .collect();
                let _ = command.reply.send(acks);
            }
        });
        begin_generation(&mut mgr);
        let mut replacement = super::bfd::bfd_params(peer, false);
        replacement.revision = 1;
        mgr.bfd_coupling.as_mut().unwrap().pending = Some(if removed {
            HashMap::new()
        } else {
            HashMap::from([(peer, replacement)])
        });

        states.send(down(peer));
        assert_eq!(mgr.serve_bfd_events(OWNED_WALK_EVENT_BUDGET).await, 1);
        assert!(reaches(&sessions[0].bfd_downs, 1).await);
        mgr.commit_bfd_reload(None).await.unwrap();

        if removed {
            assert!(reaches(&sessions[0].starts, 1).await, "released at commit");
        } else {
            assert!(mgr.bfd_withholding(&peer), "the new session is Down");
            assert!(!reaches(&sessions[0].starts, 1).await);
            let mut now_up = up(peer);
            now_up.revision = 1;
            states.send(now_up);
            let change = PeerManager::receive_bfd_state_change(&mut mgr.bfd_coupling).await;
            mgr.handle_bfd_state_change(change).await;
            assert!(reaches(&sessions[0].starts, 1).await);
        }
        assert!(!mgr.bfd_withholding(&peer), "removed={removed}");
        assert_eq!(sessions[0].bfd_downs.load(Ordering::SeqCst), 1);
        assert_eq!(sessions[0].starts.load(Ordering::SeqCst), 1);
        actor.abort();
    }
}

/// E-3, forward: two session tasks end while the walk runs. The peer whose
/// unit has committed restarts on the candidate chain. The peer the walk
/// has not reached restarts on its prior chain, and the walk then applies
/// the candidate to that new session. The walk commits.
///
/// LOAD-BEARING: with no seam the walk reaches the second peer with its
/// dead session, the hot-apply fails and the walk rolls back.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one test holds two crashing sessions, the scripted RIB and both re-established sessions"
)]
async fn session_crash_mid_walk_restarts_on_the_chain_the_walk_holds() {
    let applied = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let pending = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(1);
    let mut listeners = Vec::new();
    let mut triggers = Vec::new();
    let mut exits = Vec::new();
    let mut crashed_sessions = Vec::new();
    for peer in [applied, pending] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (crash, crashed) = oneshot::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let session_id = u64::try_from(mgr.peers.len()).unwrap() + 1;
        let exit = SessionTaskExitNotice::new(
            Some(mgr.session_notify_tx.clone()),
            SessionIdentity::primary(session_id),
            peer,
        );
        insert_test_managed_peer(
            &mut mgr,
            peer,
            walk_session(
                peer,
                Arc::default(),
                Some((exit, crashed, Arc::clone(&exited))),
            ),
            false,
        );
        mgr.peers
            .get_mut(&key(peer))
            .unwrap()
            .transport_config
            .remote_addr = listener.local_addr().unwrap();
        listeners.push(listener);
        triggers.push(crash);
        exits.push(exited);
        crashed_sessions.push(session_id);
    }
    let (registered_tx, mut registered) = mpsc::unbounded_channel();
    let rib = tokio::spawn(async move {
        let mut batches = 0;
        while let Some(update) = rib_rx.recv().await {
            match update {
                update @ RibUpdate::ReplacePeerExportPoliciesAuthoritatively { .. } => {
                    batches += 1;
                    // The second unit's batch: the first unit has committed
                    // and the third has not started.
                    if batches == 2 {
                        for (crash, exited) in triggers.drain(..).zip(&exits) {
                            crash.send(()).unwrap();
                            set(exited).await;
                        }
                    }
                    answer(update);
                }
                RibUpdate::PeerUp {
                    session_id,
                    export_policy,
                    ..
                } => {
                    let _ = registered_tx.send((session_id, export_policy));
                }
                update => answer(update),
            }
        }
        batches
    });

    // Walked in this order: the applied peer, a bystander, the pending peer.
    let order = [applied, peers[0], pending];
    let targets = distinct_targets(&order);
    let candidate = |peer: IpAddr| {
        targets
            .iter()
            .find(|target| target.address == peer)
            .unwrap()
            .export_policy
            .clone()
    };
    let (applied_chain, pending_chain) = (candidate(applied), candidate(pending));
    let result = mgr
        .apply_resolved_policy_snapshot_classified(targets, true)
        .await;
    assert!(
        result.is_ok(),
        "{:?}",
        result.err().map(|failure| failure.message().to_owned())
    );
    let mut restarted = Vec::new();
    for (peer, crashed_session) in [applied, pending].into_iter().zip(&crashed_sessions) {
        let session_id = mgr.peers[&key(peer)].session_id();
        assert_ne!(session_id, *crashed_session, "{peer} was replaced mid-walk");
        restarted.push(session_id);
    }
    assert_eq!(mgr.peers[&key(applied)].export_policy, applied_chain);
    assert_eq!(mgr.peers[&key(pending)].export_policy, pending_chain);

    // Each restarted session registers with the chain it holds.
    let _first = accept_and_establish(&listeners[0]).await;
    let _second = accept_and_establish(&listeners[1]).await;
    let mut chains = HashMap::new();
    while chains.len() < 2 {
        let (session_id, export_policy) =
            tokio::time::timeout(Duration::from_secs(5), registered.recv())
                .await
                .expect("both restarted sessions register")
                .unwrap();
        chains.insert(session_id, export_policy);
    }
    assert_eq!(chains[&restarted[0]], applied_chain);
    assert_eq!(
        chains[&restarted[1]], pending_chain,
        "the walk applied the candidate to the session that replaced the dead one"
    );
    for peer in [applied, pending] {
        mgr.delete_peer(key(peer), false).await.unwrap();
    }
    drop(mgr);
    assert_eq!(
        rib.await.unwrap(),
        2,
        "a peer that is down when the walk reaches it has no RIB step"
    );
}

/// A non-strict peer's BFD Down and the end of its session task are both
/// queued when a walk reaches a seam. The seam takes the hold and then
/// replaces the session. The replacement is not started while the hold
/// stands: the BFD Up that releases the hold sends its `Start`.
///
/// LOAD-BEARING: a replacement withheld only for a strict peer is started
/// at once, over a path BFD reports down, and the peer stays marked held.
#[tokio::test]
async fn crash_replacement_of_a_bfd_held_peer_waits_for_bfd_up() {
    let Lab {
        mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(2);
    let peer = peers[1];
    let (mut mgr, states) = couple_bfd(mgr, peer);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let crashed = mgr.peers[&key(peer)].session_id();
    let managed = mgr.peers.get_mut(&key(peer)).unwrap();
    managed.transport_config.remote_addr = listener.local_addr().unwrap();
    let (notices, seam_states) = (mgr.session_notify_tx.clone(), states.clone());
    tokio::spawn(async move {
        let mut queued = false;
        while let Some(update) = rib_rx.recv().await {
            // The first unit's batch: both events wait for the seam after it.
            if is_walk_command(&update) && !std::mem::replace(&mut queued, true) {
                seam_states.send(down(peer));
                notices
                    .send(SessionNotification::TaskExited {
                        session_id: crashed,
                        role: SessionRole::Primary,
                        peer_addr: peer,
                        cause: "ended".into(),
                    })
                    .unwrap();
            }
            answer(update);
        }
    });
    let result = mgr
        .apply_resolved_policy_snapshot_classified(distinct_targets(&peers), true)
        .await;
    assert!(
        result.is_ok(),
        "{:?}",
        result.err().map(|failure| failure.message().to_owned())
    );
    let replacement = &mgr.peers[&key(peer)];
    assert_ne!(replacement.session_id(), crashed);
    assert!(mgr.bfd_withholding(&peer));
    // Answered after any `Start` the replacement was sent.
    let state = replacement
        .handle()
        .query_state_timeout(Duration::from_secs(5))
        .await
        .expect("the replacement answers");
    assert_eq!(state.fsm_state, SessionState::Idle);

    states.send(up(peer));
    let change = PeerManager::receive_bfd_state_change(&mut mgr.bfd_coupling).await;
    mgr.handle_bfd_state_change(change).await;
    assert!(!mgr.bfd_withholding(&peer));
    tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the BFD Up starts the replacement")
        .unwrap();
}

/// A dynamic Established peer at `addr` (session 50) whose task panics when
/// the returned sender fires; the flag is set once its exit notice is queued.
fn insert_crashing_dynamic_peer(
    mgr: &mut PeerManager,
    addr: IpAddr,
) -> (oneshot::Sender<()>, Arc<AtomicBool>) {
    let (crash, crashed) = oneshot::channel();
    let exited = Arc::new(AtomicBool::new(false));
    let exit = SessionTaskExitNotice::new(
        Some(mgr.session_notify_tx.clone()),
        SessionIdentity::primary(50),
        addr,
    );
    insert_test_dynamic_managed_peer(
        mgr,
        addr,
        50,
        walk_session(
            addr,
            Arc::default(),
            Some((exit, crashed, Arc::clone(&exited))),
        ),
        true,
        IpAddr::V4(Ipv4Addr::new(10, 42, 9, 0)),
        24,
        "dynamic",
    );
    (crash, exited)
}

/// Handle the task exit the walk held and check it retired `peer`.
async fn retire_held_peer(mgr: &mut PeerManager, peer: IpAddr) {
    let held = mgr
        .session_notify_rx
        .try_recv()
        .expect("the held notification is back on the channel");
    mgr.handle_session_notification(held).await;
    assert!(
        !mgr.peers.contains_key(&key(peer)),
        "retired after the walk"
    );
}

/// E-4 in an export pair: a dynamic member's session legs succeed, then its
/// task ends while the walk waits for the pair's RIB batch, and the seam
/// after the batch holds the exit. The member owes no deferred Route
/// Refresh, and the walk commits.
///
/// LOAD-BEARING: the deferred refresh probes the ended session, finds it
/// gone and rolls the reload back.
#[tokio::test(start_paused = true)]
async fn dynamic_pair_member_task_exit_owes_no_deferred_refresh() {
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(1);
    let dynamic = IpAddr::V4(Ipv4Addr::new(10, 42, 9, 1));
    let (crash, exited) = insert_crashing_dynamic_peer(&mut mgr, dynamic);
    let rib = tokio::spawn(async move {
        let mut crash = Some(crash);
        while let Some(update) = rib_rx.recv().await {
            // The dynamic member's batch: its session legs are done and its
            // Route Refresh is deferred past this reply.
            if is_walk_command(&update)
                && let Some(crash) = crash.take()
            {
                crash.send(()).unwrap();
                set(&exited).await;
            }
            answer(update);
        }
    });
    let mut targets = distinct_targets(&[dynamic, peers[0]]);
    targets[0].import_policy = Some(deny_policy_chain());
    let expected = targets[0].clone();
    let result = mgr
        .apply_resolved_policy_snapshot_classified(targets, true)
        .await;
    assert!(
        result.is_ok(),
        "{:?}",
        result.err().map(|failure| failure.message().to_owned())
    );
    let managed = &mgr.peers[&key(dynamic)];
    assert_eq!(managed.import_policy, expected.import_policy);
    assert_eq!(managed.export_policy, expected.export_policy);
    assert!(!managed.pending_refresh, "the member owes nothing");
    retire_held_peer(&mut mgr, dynamic).await;
    drop(mgr);
    rib.await.unwrap();
}

/// E-4, rollback: a dynamic peer answers its restore step, which owes a
/// Route Refresh because its forward unit fired one, and its task then
/// ends. A rollback seam holds the exit, the ended session is sent no
/// refresh, and the rollback is exact.
///
/// LOAD-BEARING: the refresh goes to the ended session and fails, which
/// leaves the peer owing a refresh and the rollback ambiguous.
#[tokio::test(start_paused = true)]
async fn dynamic_task_exit_after_its_restore_step_owes_no_refresh() {
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        sessions,
        ..
    } = lab(2);
    let dynamic = IpAddr::V4(Ipv4Addr::new(10, 42, 9, 1));
    let (crash, exited) = insert_crashing_dynamic_peer(&mut mgr, dynamic);
    let hooked = Arc::clone(&sessions[0]);
    let rib = tokio::spawn(async move {
        let mut commands = 0;
        let mut crash = Some(crash);
        let mut exited_before_restore = None;
        while let Some(update) = rib_rx.recv().await {
            if !is_walk_command(&update) {
                answer(update);
                continue;
            }
            commands += 1;
            match update {
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. }
                    if commands == 3 =>
                {
                    // The rollback restores newest first: the first peer's
                    // restore step, after the dynamic peer's, ends its task.
                    let crash = crash.take().unwrap();
                    *hooked.on_export.lock().unwrap() = Some(Box::new(move || {
                        let _ = crash.send(());
                    }));
                    let _ = reply.send(Err(RibCommandError::internal("refused")));
                }
                update @ RibUpdate::RestorePeerExportPoliciesAuthoritatively { .. } => {
                    exited_before_restore.get_or_insert(exited.load(Ordering::SeqCst));
                    answer(update);
                }
                update => answer(update),
            }
        }
        exited_before_restore
    });
    let mut targets = distinct_targets(&[peers[0], dynamic, peers[1]]);
    targets[1].import_policy = Some(deny_policy_chain());
    let failure = mgr
        .apply_resolved_policy_snapshot_classified(targets, true)
        .await
        .expect_err("the third batch is refused");
    assert_eq!(
        failure.kind,
        PolicySnapshotFailureKind::FullyCompensated,
        "{} ({})",
        failure.message(),
        failure.code.as_str()
    );
    let managed = &mgr.peers[&key(dynamic)];
    assert_eq!(managed.import_policy, None);
    assert_eq!(managed.export_policy, None);
    assert!(!managed.pending_refresh, "the peer owes nothing");
    retire_held_peer(&mut mgr, dynamic).await;
    drop(mgr);
    assert_eq!(
        rib.await.unwrap(),
        Some(true),
        "the task ended before the rollback's refreshes"
    );
}

/// A dynamic peer that owed a Route Refresh before the walk, whose task ends
/// before the walk reaches it: the walk and then the rollback adopt its
/// chains without a session step. The peer is retired when the walk ends,
/// so the debt it was captured with is not the rollback's to restore, and
/// the rollback is exact.
///
/// LOAD-BEARING: the exact-pending scan compares the adopted peer's cleared
/// flags with its captured debt and reports the rollback ambiguous.
#[tokio::test(start_paused = true)]
async fn held_task_exit_of_an_indebted_dynamic_peer_keeps_the_rollback_exact() {
    let Lab {
        mut mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(2);
    let dynamic = IpAddr::V4(Ipv4Addr::new(10, 42, 9, 1));
    let (crash, exited) = insert_crashing_dynamic_peer(&mut mgr, dynamic);
    mgr.peers.get_mut(&key(dynamic)).unwrap().pending_refresh = true;
    let rib = tokio::spawn(async move {
        let mut commands = 0;
        let mut crash = Some(crash);
        while let Some(update) = rib_rx.recv().await {
            if !is_walk_command(&update) {
                answer(update);
                continue;
            }
            commands += 1;
            match update {
                // The first unit's batch: the walk has not reached the
                // dynamic peer, and holds its exit at the seam after it.
                update if commands == 1 => {
                    crash.take().unwrap().send(()).unwrap();
                    set(&exited).await;
                    answer(update);
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. }
                    if commands == 2 =>
                {
                    let _ = reply.send(Err(RibCommandError::internal("refused")));
                }
                update => answer(update),
            }
        }
    });
    let failure = mgr
        .apply_resolved_policy_snapshot_classified(
            distinct_targets(&[peers[0], dynamic, peers[1]]),
            true,
        )
        .await
        .expect_err("the last batch is refused");
    assert_eq!(
        failure.kind,
        PolicySnapshotFailureKind::FullyCompensated,
        "{} ({})",
        failure.message(),
        failure.code.as_str()
    );
    assert_eq!(mgr.peers[&key(dynamic)].export_policy, None);
    retire_held_peer(&mut mgr, dynamic).await;
    drop(mgr);
    rib.await.unwrap();
}

/// The exit notice of `peer`'s current session task.
fn task_exited(mgr: &PeerManager, peer: IpAddr) -> SessionNotification {
    SessionNotification::TaskExited {
        session_id: mgr.peers[&key(peer)].session_id(),
        role: SessionRole::Primary,
        peer_addr: peer,
        cause: "ended".into(),
    }
}

/// A non-strict peer is held by a BFD Down and its session task has ended.
/// The BFD Up that permits BGP again is handled before the task's exit, as
/// a seam handles them, BFD first: the Up's `Start` meets the closed
/// channel, and the hold stays. The exit republishes the desired state, the
/// BFD actor re-confirms Up, and that acknowledgement starts the
/// replacement. Inside a generation the Up stays queued and the replacement
/// is held until the generation has ended.
///
/// LOAD-BEARING: with no republication nothing reports BFD Up again, so the
/// replacement stays Idle and held until a BFD flap.
#[tokio::test]
async fn bfd_up_handled_before_a_held_peers_task_exit_starts_the_replacement() {
    for in_generation in [false, true] {
        let Lab {
            mut mgr,
            mut rib_rx,
            peers,
            ..
        } = lab(2);
        let peer = peers[1];
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (commands, ended) = mpsc::channel(1);
        drop(ended);
        insert_test_managed_peer(
            &mut mgr,
            peer,
            PeerHandle::from_parts(commands, tokio::spawn(async { Ok(()) })),
            false,
        );
        mgr.peers
            .get_mut(&key(peer))
            .unwrap()
            .transport_config
            .remote_addr = listener.local_addr().unwrap();
        let configured = HashMap::from([(peer, super::bfd::bfd_params(peer, false))]);
        let (desired_tx, mut desired_rx) =
            watch::channel(crate::bfd_runtime::BfdRuntimeConfig::default());
        let (states, states_rx) = crate::bfd_runtime::state_change_channel();
        let mut mgr = mgr.with_bfd_coupling(desired_tx, states_rx, configured);
        mgr.bfd_coupling.as_mut().unwrap().held_down.insert(peer);
        desired_rx.mark_unchanged();
        if in_generation {
            begin_generation(&mut mgr);
        }
        let ended_session = mgr.peers[&key(peer)].session_id();
        let (notices, seam_states) = (mgr.session_notify_tx.clone(), states.clone());
        let mut notice = Some(task_exited(&mgr, peer));
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                // The only unit's batch: both events wait for the seam after it.
                if is_walk_command(&update)
                    && let Some(notice) = notice.take()
                {
                    seam_states.send(up(peer));
                    notices.send(notice).unwrap();
                }
                answer(update);
            }
        });
        let result = mgr
            .apply_resolved_policy_snapshot_classified(distinct_targets(&peers[..1]), true)
            .await;
        assert!(
            result.is_ok(),
            "{:?}",
            result.err().map(|failure| failure.message().to_owned())
        );
        assert_ne!(mgr.peers[&key(peer)].session_id(), ended_session);
        if in_generation {
            assert!(mgr.bfd_withholding(&peer), "the generation keeps the hold");
            let state = mgr.peers[&key(peer)]
                .handle()
                .query_state_timeout(Duration::from_secs(5))
                .await
                .expect("the replacement answers");
            assert_eq!(state.fsm_state, SessionState::Idle);
            mgr.abort_bfd_reload();
        }
        // The BFD actor answers a republished desired state by re-confirming
        // each session's level.
        if desired_rx.has_changed().unwrap() {
            let mut ack = up(peer);
            ack.resync = true;
            states.send(ack);
        }
        mgr.serve_bfd_events(OWNED_WALK_EVENT_BUDGET).await;
        assert!(!mgr.bfd_withholding(&peer), "in_generation={in_generation}");
        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap_or_else(|_| panic!("in_generation={in_generation}: the replacement is started"))
            .unwrap();
    }
}

/// The running configuration couples a peer to BFD non-strictly and the
/// candidate strictly. Its session task ends inside the generation, and the
/// replacement takes the candidate's initial hold. A genuine BFD Down that
/// follows is taken at the seam and recorded as a prior hold, so the
/// replacement stays held without a dial once the generation has ended,
/// aborted or committed, and the BFD Up starts it.
///
/// LOAD-BEARING: a seam that leaves the Down queued for an already-held peer
/// keeps only the candidate's hold, which the abort releases with a `Start`
/// although BFD is Down.
#[tokio::test]
async fn bfd_down_after_a_candidate_hold_outlives_the_generation() {
    for commit in [false, true] {
        let Lab {
            mgr,
            mut rib_rx,
            peers,
            ..
        } = lab(1);
        let peer = peers[0];
        let (mgr, states) = couple_bfd(mgr, peer);
        let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
        let mut mgr = mgr.with_bfd_reload(reload_tx);
        // The actor re-reports every desired session's level: Down.
        let actor = tokio::spawn(async move {
            while let Some(command) = reload_rx.recv().await {
                let acks = command
                    .desired
                    .sessions
                    .iter()
                    .map(|params| {
                        let mut ack = down(params.peer);
                        ack.revision = params.revision;
                        ack.resync = true;
                        ack
                    })
                    .collect();
                let _ = command.reply.send(acks);
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        mgr.peers
            .get_mut(&key(peer))
            .unwrap()
            .transport_config
            .remote_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                answer(update);
            }
        });
        begin_generation(&mut mgr);
        mgr.bfd_coupling.as_mut().unwrap().pending =
            Some(HashMap::from([(peer, super::bfd::bfd_params(peer, true))]));

        mgr.handle_session_notification(task_exited(&mgr, peer))
            .await;
        assert!(
            mgr.bfd_withholding(&peer),
            "the candidate holds the replacement"
        );
        states.send(down(peer));
        mgr.serve_bfd_events(OWNED_WALK_EVENT_BUDGET).await;
        if commit {
            mgr.commit_bfd_reload(None).await.unwrap();
        } else {
            mgr.abort_bfd_reload();
        }
        // Not released by the generation's end, so no `Start` was sent.
        assert!(mgr.bfd_withholding(&peer), "commit={commit}: at the end");
        // The run loop then handles whatever is still queued.
        mgr.serve_bfd_events(OWNED_WALK_EVENT_BUDGET).await;
        assert!(mgr.bfd_withholding(&peer), "commit={commit}");
        assert!(
            tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .is_err(),
            "commit={commit}: the replacement dialed while BFD is Down"
        );

        states.send(up(peer));
        mgr.serve_bfd_events(OWNED_WALK_EVENT_BUDGET).await;
        assert!(!mgr.bfd_withholding(&peer), "commit={commit}");
        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap_or_else(|_| panic!("commit={commit}: the BFD Up starts the replacement"))
            .unwrap();
        actor.abort();
    }
}

/// A static peer held by a BFD Down whose replacement dials the returned
/// listener, under a RIB that answers everything.
async fn held_bfd_peer() -> (PeerManager, IpAddr, TcpListener) {
    let Lab {
        mgr,
        mut rib_rx,
        peers,
        ..
    } = lab(1);
    let peer = peers[0];
    let (mut mgr, _states) = couple_bfd(mgr, peer);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    mgr.peers
        .get_mut(&key(peer))
        .unwrap()
        .transport_config
        .remote_addr = listener.local_addr().unwrap();
    mgr.bfd_coupling.as_mut().unwrap().held_down.insert(peer);
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            answer(update);
        }
    });
    (mgr, peer, listener)
}

/// Inside a generation, a `Start` retry pending for a held peer's session
/// moves to the session that replaces it after a crash, and is delivered
/// once the generation has ended.
///
/// LOAD-BEARING: a retry left keyed to the ended session is dropped, and the
/// replacement stays held.
#[tokio::test]
async fn a_start_retry_moves_to_the_replacement_inside_a_generation() {
    let (mut mgr, peer, listener) = held_bfd_peer().await;
    mgr.schedule_bfd_retry(peer, true);
    begin_generation(&mut mgr);
    let crashed = mgr.peers[&key(peer)].session_id();
    mgr.handle_session_notification(task_exited(&mgr, peer))
        .await;
    assert_ne!(mgr.peers[&key(peer)].session_id(), crashed);
    mgr.abort_bfd_reload();
    tokio::time::sleep(Duration::from_millis(150)).await;
    mgr.retry_due_bfd_commands();
    assert!(!mgr.bfd_withholding(&peer));
    tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the retry starts the replacement")
        .unwrap();
}

/// Outside a generation, a held peer owed a `Start` (a release whose
/// delivery was being retried, or a relaxed strict hold) is released when
/// its session task ends: the replacement is started at once.
///
/// LOAD-BEARING: without the release the replacement stays Idle and held
/// until a later BFD edge.
#[tokio::test]
async fn an_owed_start_goes_to_the_replacement_at_once() {
    for relaxed in [false, true] {
        let (mut mgr, peer, listener) = held_bfd_peer().await;
        if relaxed {
            mgr.mark_bfd_withheld(peer);
        } else {
            mgr.schedule_bfd_retry(peer, true);
        }
        mgr.handle_session_notification(task_exited(&mgr, peer))
            .await;
        assert!(!mgr.bfd_withholding(&peer), "relaxed={relaxed}");
        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap_or_else(|_| panic!("relaxed={relaxed}: the replacement is started"))
            .unwrap();
    }
}
