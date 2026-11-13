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

/// E-5, flood: one seam serves at most the per-kind budget of session
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
                // The last forward command: one seam follows it.
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
        FLOOD - OWNED_WALK_EVENT_BUDGET,
        "one seam serves its budget and no more"
    );
    drop(mgr);
    rib.await.unwrap();
}

/// E-5, stall: events that keep arriving while a unit never completes do
/// not keep the walk alive. It rolls back one stall timeout after its last
/// completed unit, plus only the time the seam after that unit spent
/// serving, which is not the RIB's.
///
/// The seam's service here takes `PEER_LIFECYCLE_COMMAND_TIMEOUT`: the BFD
/// Down it serves stops a pending inbound candidate that never exits.
///
/// LOAD-BEARING: charging the service time to the stall budget ends the
/// walk that much early.
#[tokio::test(start_paused = true)]
async fn events_do_not_renew_a_stalled_walk() {
    let first_unit = Duration::from_secs(80);
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
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. } => {
                    commands += 1;
                    if commands == 1 {
                        tokio::time::sleep(first_unit).await;
                        states.send(down(held));
                        let _ = reply.send(Ok(Vec::new()));
                    } else {
                        stalled.push(reply);
                    }
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
        first_unit + PEER_LIFECYCLE_COMMAND_TIMEOUT + RIB_BATCH_REPLY_TIMEOUT
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
