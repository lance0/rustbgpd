use super::*;
use rustbgpd_rib::PeerId;

use rustbgpd_api::peer_types::OwnedDampeningControlOutcome as Outcome;
use rustbgpd_rib::dampening::{
    DampeningAdmission, DampeningCapacityNotice, DampeningCapacityReason, DampeningHistoryLimits,
    DampeningOwner, DampeningParameters,
};
use rustbgpd_rib::update::{PeerSourceContext, WireRoutesReceived};
use std::num::NonZeroU64;

struct CapacityFixture {
    manager: PeerManager,
    peer: PeerKey,
    admission: DampeningAdmission,
    notices: mpsc::UnboundedReceiver<DampeningCapacityNotice>,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_task: tokio::task::JoinHandle<()>,
    primary_joined: Arc<AtomicBool>,
}

struct ProducerExited(Arc<AtomicBool>);
impl Drop for ProducerExited {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

async fn tracked_producer() -> (PeerHandle, Arc<AtomicBool>) {
    let joined = Arc::new(AtomicBool::new(false));
    let flag = joined.clone();
    let (started, ready) = oneshot::channel();
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let _guard = ProducerExited(flag);
        started.send(()).unwrap();
        while let Some(command) = rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
        }
        Ok(())
    });
    ready.await.unwrap();
    (PeerHandle::from_parts(tx, task), joined)
}

async fn publish(
    rib_tx: &mpsc::Sender<RibUpdate>,
    publication: u64,
    owners: Vec<Arc<DampeningOwner>>,
) {
    let (reply, response) = oneshot::channel();
    rib_tx
        .send(RibUpdate::PublishDampeningOwners {
            publication,
            owners,
            reply,
        })
        .await
        .unwrap();
    response.await.unwrap().unwrap();
}

async fn register_source(
    rib_tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    admission: DampeningAdmission,
) {
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    rib_tx
        .send(RibUpdate::SetPeerSourceContext {
            peer: PeerId::from_addr(peer),
            session_id: 1,
            context: Arc::new(PeerSourceContext {
                exact_export_families: Vec::new(),
                dampening_admission: Some(admission),
                peer_interface: None,
                accepted_dynamic_range: None,
                route_server_client: false,
            }),
        })
        .await
        .unwrap();
    rib_tx
        .send(RibUpdate::PeerUp {
            supersedes: None,
            peer: PeerId::from_addr(peer),
            session_id: 1,
            peer_asn: 65002,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: Vec::new(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: Vec::new(),
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        })
        .await
        .unwrap();
    // Registration and wire admission are separate so tests can hold the
    // original batch while the transport's BackToIdle reaches the manager.
}

fn empty_wire_batch(peer: IpAddr) -> RibUpdate {
    RibUpdate::WireRoutesReceived(WireRoutesReceived {
        peer: PeerId::from_addr(peer),
        session_id: 1,
        announced: Vec::new(),
        withdrawn: Vec::new(),
        original_unicast_withdrawals: 0,
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    })
}

impl CapacityFixture {
    async fn new() -> Self {
        let (rib_tx, rib_rx) = mpsc::channel(32);
        let (_query_tx, query_rx) = mpsc::channel(1);
        let (notice_tx, notices) = mpsc::unbounded_channel();
        let mut rib =
            rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
        rib.install_dampening_history_for_test(
            DampeningParameters::default(),
            DampeningHistoryLimits {
                owners: 4,
                sources: 1,
                history_keys: 2,
                source_history_keys: 2,
            },
            notice_tx,
        )
        .unwrap();
        let rib_task = tokio::spawn(rib.run());
        let owner = Arc::new(DampeningOwner::new(NonZeroU64::new(1).unwrap()));
        let filler = Arc::new(DampeningOwner::new(NonZeroU64::new(2).unwrap()));
        let admission = DampeningAdmission::new(owner.clone());
        publish(&rib_tx, 1, vec![owner, filler.clone()]).await;
        let filler_peer = "192.0.2.2".parse().unwrap();
        register_source(&rib_tx, filler_peer, DampeningAdmission::new(filler)).await;
        rib_tx.send(empty_wire_batch(filler_peer)).await.unwrap();
        let peer = key("192.0.2.1".parse().unwrap());
        let mut manager = test_peer_manager();
        manager.rib_tx = rib_tx.clone();
        manager.next_session_id = 10;
        let (handle, primary_joined) = tracked_producer().await;
        insert_test_managed_peer(&mut manager, peer.address, handle, false);
        manager
            .peers
            .get_mut(&peer)
            .unwrap()
            .transport_config
            .dampening_admission = Some(admission.clone());
        register_source(&rib_tx, peer.address, admission.clone()).await;
        Self {
            manager,
            peer,
            admission,
            notices,
            rib_tx,
            rib_task,
            primary_joined,
        }
    }

    async fn exhaust(&mut self) -> DampeningCapacityNotice {
        self.rib_tx
            .send(empty_wire_batch(self.peer.address))
            .await
            .unwrap();
        let notice = tokio::time::timeout(Duration::from_secs(2), self.notices.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(notice.reason, DampeningCapacityReason::Sources);
        assert!(self.admission.is_blocked());
        assert!(!self.admission.capacity_disable_complete());
        notice
    }

    async fn disable_and_free_capacity(&mut self) {
        let notice = self.exhaust().await;
        assert!(matches!(
            self.manager.disable_dampening_capacity(notice).await,
            Outcome::Applied
        ));
        publish(&self.rib_tx, 2, vec![self.admission.owner.clone()]).await;
        // Primary-lane barrier also gives bounded retirement its next actor turn.
        let (reply, response) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        response.await.unwrap();
    }

    async fn replace_idle(&mut self, replacement: PeerHandle) {
        let session = self.manager.peers.get(&self.peer).unwrap().session_id();
        let (old, _) = self
            .manager
            .peers
            .replace_handle(&self.peer, replacement, session)
            .unwrap();
        old.abort_for_transport_safety_and_wait().await;
    }
}

/// An admission that a real RIB blocked for source capacity. Only the RIB can
/// set the block, so other suites borrow it from here.
pub(super) async fn capacity_blocked_admission() -> DampeningAdmission {
    let mut fixture = Box::pin(CapacityFixture::new()).await;
    fixture.exhaust().await;
    fixture.rib_task.abort();
    fixture.admission
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one controlled disable interleaving checks producer joins, barrier acknowledgement, and source-local recovery"
)]
async fn capacity_disable_joins_both_producers_before_primary_barrier() {
    let mut fixture = Box::pin(CapacityFixture::new()).await;
    let notice = fixture.exhaust().await;
    assert!(matches!(
        fixture
            .manager
            .enable_peer_owned(fixture.peer.clone())
            .await,
        Outcome::RejectedNoEffect(_)
    ));
    fixture
        .manager
        .peers
        .get_mut(&fixture.peer)
        .unwrap()
        .is_dynamic = true;
    fixture.manager.dynamic_peer_count = 1;
    fixture
        .manager
        .handle_session_notification(SessionNotification::BackToIdle {
            peer_addr: fixture.peer.address,
            session_id: 1,
            role: rustbgpd_transport::SessionRole::Primary,
        })
        .await;
    assert!(
        fixture.manager.peers.get(&fixture.peer).is_some(),
        "blocked dynamic source retains its recovery target"
    );
    let (candidate, candidate_joined) = tracked_producer().await;
    fixture
        .manager
        .peers
        .get_mut(&fixture.peer)
        .unwrap()
        .pending_inbound = Some(PendingInbound {
        recovery_reset: None,
        handle: candidate,
        session_id: 2,
    });
    fixture.manager.register_session(2, &fixture.peer);
    let (proxy_tx, mut proxy_rx) = mpsc::channel(8);
    fixture.manager.rib_tx = proxy_tx;
    let admission = fixture.admission.clone();
    let observer = async {
        let mut down = Vec::new();
        loop {
            let command = proxy_rx.recv().await.unwrap();
            match command {
                RibUpdate::PeerDown { peer, session_id } => {
                    assert_eq!(peer, PeerId::from_addr(fixture.peer.address));
                    if session_id == 2 {
                        assert!(candidate_joined.load(Ordering::SeqCst));
                    }
                    if session_id == 1 {
                        assert!(fixture.primary_joined.load(Ordering::SeqCst));
                    }
                    down.push(session_id);
                    fixture
                        .rib_tx
                        .send(RibUpdate::PeerDown { peer, session_id })
                        .await
                        .unwrap();
                }
                RibUpdate::QueryLocRibCount { reply } => {
                    assert_eq!(down, [2, 1]);
                    assert!(admission.is_blocked());
                    assert!(
                        !admission.capacity_disable_complete(),
                        "enqueueing the barrier cannot acknowledge disable"
                    );
                    fixture
                        .rib_tx
                        .send(RibUpdate::QueryLocRibCount { reply })
                        .await
                        .unwrap();
                    break;
                }
                _ => panic!("unexpected capacity-disable command"),
            }
        }
    };
    let (outcome, ()) = tokio::join!(
        fixture.manager.disable_dampening_capacity(notice.clone()),
        observer
    );
    assert!(matches!(outcome, Outcome::Applied));
    assert!(fixture.admission.capacity_disable_complete());
    assert!(!fixture.manager.peers.get(&fixture.peer).unwrap().enabled);
    fixture.manager.rib_tx = fixture.rib_tx.clone();
    assert!(matches!(
        fixture
            .manager
            .enable_peer_owned(fixture.peer.clone())
            .await,
        Outcome::RejectedNoEffect(_)
    ));
    assert!(
        fixture.admission.is_blocked(),
        "failed headroom reservation must remain disabled"
    );
    let replacement_owner = Arc::new(DampeningOwner::new(NonZeroU64::new(3).unwrap()));
    let managed = fixture.manager.peers.get_mut(&fixture.peer).unwrap();
    managed.transport_config.dampening_admission = Some(DampeningAdmission::new(replacement_owner));
    managed.enabled = true;
    assert!(matches!(
        fixture
            .manager
            .disable_dampening_capacity(notice.clone())
            .await,
        Outcome::Applied
    ));
    assert!(
        fixture.manager.peers.get(&fixture.peer).unwrap().enabled,
        "old owner notice cannot disable a replacement at the same address"
    );
    fixture.rib_task.abort();
}

#[tokio::test]
async fn capacity_enable_waits_for_prepare_and_complete_acknowledgements() {
    let mut fixture = Box::pin(CapacityFixture::new()).await;
    fixture.disable_and_free_capacity().await;
    let counters = Arc::new(FakePeerCounters::default());
    fixture
        .replace_idle(fake_peer_handle(
            fixture.peer.address,
            SessionState::Idle,
            None,
            counters.clone(),
        ))
        .await;
    let (proxy_tx, mut proxy_rx) = mpsc::channel(8);
    fixture.manager.rib_tx = proxy_tx;
    let peer = fixture.peer.clone();
    let mut enabling = tokio::spawn(async move {
        let outcome = fixture.manager.enable_peer_owned(peer).await;
        (outcome, fixture.manager)
    });
    let RibUpdate::PrepareDampeningEnable {
        source,
        reason,
        reply,
    } = proxy_rx.recv().await.unwrap()
    else {
        panic!("expected Prepare")
    };
    let (real_reply, response) = oneshot::channel();
    fixture
        .rib_tx
        .send(RibUpdate::PrepareDampeningEnable {
            source,
            reason,
            reply: real_reply,
        })
        .await
        .unwrap();
    let receipt = response.await.unwrap().unwrap();
    assert!(!fixture.admission.is_blocked());
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        0,
        "Start waits for the owned Prepare receipt"
    );
    assert!(!enabling.is_finished());
    // A new publication must remain fenced while the reservation is outstanding.
    let (publication_reply, publication_response) = oneshot::channel();
    fixture
        .rib_tx
        .send(RibUpdate::PublishDampeningOwners {
            publication: 3,
            owners: vec![fixture.admission.owner.clone()],
            reply: publication_reply,
        })
        .await
        .unwrap();
    assert!(matches!(
        publication_response.await.unwrap(),
        Err(rustbgpd_rib::dampening::DampeningControlError::RecoveryInProgress)
    ));
    reply.send(Ok(receipt)).unwrap();
    let RibUpdate::CompleteDampeningEnable {
        receipt,
        enabled,
        reply,
    } = proxy_rx.recv().await.unwrap()
    else {
        panic!("expected Complete")
    };
    assert!(enabled);
    assert!(
        !enabling.is_finished(),
        "Start admission cannot complete owned enable"
    );
    fixture
        .rib_tx
        .send(RibUpdate::CompleteDampeningEnable {
            receipt,
            enabled,
            reply,
        })
        .await
        .unwrap();
    let (outcome, manager) = (&mut enabling).await.unwrap();
    assert!(matches!(outcome, Outcome::Applied));
    assert!(manager.peers.get(&fixture.peer).unwrap().enabled);
    assert!(!fixture.admission.is_blocked());
    fixture.rib_task.abort();
}

#[tokio::test]
async fn capacity_enable_failed_start_reblocks_but_lost_receipts_are_ambiguous() {
    for lost_reply in [None, Some(false), Some(true)] {
        let mut fixture = Box::pin(CapacityFixture::new()).await;
        fixture.disable_and_free_capacity().await;
        let replacement = if lost_reply.is_none() {
            let (tx, rx) = mpsc::channel(1);
            drop(rx);
            PeerHandle::from_parts(tx, tokio::spawn(async { Ok(()) }))
        } else {
            fake_peer_handle(
                fixture.peer.address,
                SessionState::Idle,
                None,
                Arc::new(FakePeerCounters::default()),
            )
        };
        fixture.replace_idle(replacement).await;
        let (proxy_tx, mut proxy_rx) = mpsc::channel(8);
        fixture.manager.rib_tx = proxy_tx;
        let peer = fixture.peer.clone();
        let enabling = tokio::spawn(async move {
            let outcome = fixture.manager.enable_peer_owned(peer).await;
            (outcome, fixture.manager)
        });
        let RibUpdate::PrepareDampeningEnable {
            source,
            reason,
            reply,
        } = proxy_rx.recv().await.unwrap()
        else {
            panic!("expected Prepare")
        };
        let (real_reply, response) = oneshot::channel();
        fixture
            .rib_tx
            .send(RibUpdate::PrepareDampeningEnable {
                source,
                reason,
                reply: real_reply,
            })
            .await
            .unwrap();
        let receipt = response.await.unwrap().unwrap();
        if lost_reply == Some(false) {
            drop(reply);
        } else {
            reply.send(Ok(receipt)).unwrap();
            let RibUpdate::CompleteDampeningEnable {
                receipt,
                enabled,
                reply,
            } = proxy_rx.recv().await.unwrap()
            else {
                panic!("expected Complete")
            };
            assert_eq!(enabled, lost_reply.is_some());
            let (real_reply, response) = oneshot::channel();
            fixture
                .rib_tx
                .send(RibUpdate::CompleteDampeningEnable {
                    receipt,
                    enabled,
                    reply: real_reply,
                })
                .await
                .unwrap();
            response.await.unwrap().unwrap();
            if lost_reply == Some(true) {
                drop(reply);
            } else {
                reply.send(Ok(())).unwrap();
            }
        }
        let (outcome, manager) = enabling.await.unwrap();
        if lost_reply.is_none() {
            assert!(matches!(outcome, Outcome::RejectedNoEffect(_)));
            assert!(fixture.admission.is_blocked());
            assert!(fixture.admission.capacity_disable_complete());
            assert!(!manager.peers.get(&fixture.peer).unwrap().enabled);
        } else {
            assert!(matches!(outcome, Outcome::Ambiguous(_)));
        }
        fixture.rib_task.abort();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the controlled late-wire retirement race also verifies lost-barrier fail-stop without sleeps"
)]
async fn dynamic_retirement_waits_for_queued_wire_capacity_decision() {
    for acknowledge_barrier in [true, false] {
        let mut fixture = Box::pin(CapacityFixture::new()).await;
        fixture
            .manager
            .peers
            .get_mut(&fixture.peer)
            .unwrap()
            .is_dynamic = true;
        fixture.manager.dynamic_peer_count = 1;
        let (candidate, candidate_joined) = tracked_producer().await;
        fixture
            .manager
            .peers
            .get_mut(&fixture.peer)
            .unwrap()
            .pending_inbound = Some(PendingInbound {
            recovery_reset: None,
            handle: candidate,
            session_id: 2,
        });
        fixture.manager.register_session(2, &fixture.peer);
        let (proxy_tx, mut proxy_rx) = mpsc::channel(8);
        fixture.manager.rib_tx = proxy_tx.clone();
        // This original batch was emitted before BackToIdle, but the primary
        // RIB consumer has not yet reached its capacity decision.
        proxy_tx
            .send(empty_wire_batch(fixture.peer.address))
            .await
            .unwrap();
        let held_batch = proxy_rx.recv().await.unwrap();
        assert!(!fixture.admission.is_blocked());
        let peer_addr = PeerId::from_addr(fixture.peer.address);
        let retiring = tokio::spawn(async move {
            fixture
                .manager
                .handle_session_notification(SessionNotification::BackToIdle {
                    peer_addr: peer_addr.addr(),
                    session_id: 1,
                    role: rustbgpd_transport::SessionRole::Primary,
                })
                .await;
            fixture.manager
        });
        let mut down = Vec::new();
        let barrier = loop {
            match proxy_rx.recv().await.unwrap() {
                RibUpdate::PeerDown { peer, session_id } => {
                    assert_eq!(peer, peer_addr);
                    assert!(fixture.primary_joined.load(Ordering::SeqCst));
                    assert!(candidate_joined.load(Ordering::SeqCst));
                    down.push(session_id);
                }
                RibUpdate::QueryLocRibCount { reply } => break reply,
                _ => panic!("unexpected dynamic retirement command"),
            }
        };
        assert_eq!(
            down.iter().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2])
        );
        assert_eq!(down.len(), 2);
        assert!(!fixture.admission.is_blocked());
        assert!(
            !retiring.is_finished(),
            "joined producers alone cannot authorize dynamic reap"
        );
        if acknowledge_barrier {
            fixture.rib_tx.send(held_batch).await.unwrap();
            for session_id in down {
                fixture
                    .rib_tx
                    .send(RibUpdate::PeerDown {
                        peer: peer_addr,
                        session_id,
                    })
                    .await
                    .unwrap();
            }
            fixture
                .rib_tx
                .send(RibUpdate::QueryLocRibCount { reply: barrier })
                .await
                .unwrap();
        } else {
            drop(barrier);
        }
        let mut manager = retiring.await.unwrap();
        assert!(
            manager.peers.get(&fixture.peer).is_some(),
            "uncertain or blocked dynamic source retains its recovery target"
        );
        assert!(!manager.peers.get(&fixture.peer).unwrap().enabled);
        assert_eq!(manager.dynamic_peer_count, 1);
        assert_eq!(manager.dampening_control_failed, !acknowledge_barrier);
        assert!(!fixture.admission.capacity_disable_complete());
        if acknowledge_barrier {
            assert!(fixture.admission.is_blocked());
            manager.rib_tx = fixture.rib_tx.clone();
            assert!(matches!(
                manager.enable_peer_owned(fixture.peer.clone()).await,
                Outcome::RejectedNoEffect(_)
            ));
            let notice = fixture.notices.recv().await.unwrap();
            assert_eq!(notice.source.session_id, 1);
            assert_eq!(notice.reason, DampeningCapacityReason::Sources);
            assert!(matches!(
                manager.disable_dampening_capacity(notice).await,
                Outcome::Applied
            ));
            assert!(fixture.admission.capacity_disable_complete());
            assert!(!manager.peers.get(&fixture.peer).unwrap().enabled);
        } else {
            assert!(
                !fixture.admission.is_blocked(),
                "lost barrier retains the target even without an observed capacity block"
            );
        }
        fixture.rib_task.abort();
    }
}

/// How the RIB lane stands when a dynamic source's sessions have joined.
#[derive(Clone, Copy, Debug)]
enum BarrierLane {
    /// No room: the fence cannot be admitted until the RIB resumes.
    Full,
    /// Room, but an earlier update is still deferred ahead of the fence.
    DeferredAhead,
    /// The primary cannot take its Shutdown, so the session round's whole
    /// window is spent before the fence is queued.
    RoundSpent,
}

struct BarrierFixture {
    retiring: tokio::task::JoinHandle<PeerManager>,
    lane: mpsc::Receiver<RibUpdate>,
    peer: PeerKey,
    rib_task: tokio::task::JoinHandle<()>,
}

fn barrier_filler() -> RibUpdate {
    RibUpdate::ReleasePeer {
        peer: PeerId::UNASSIGNED,
    }
}

/// A dynamic wire-history source whose primary reported `BackToIdle`, with
/// the manager's RIB lane in `state`, and its retirement running.
async fn retire_dynamic_source(state: BarrierLane) -> BarrierFixture {
    let mut fixture = Box::pin(CapacityFixture::new()).await;
    fixture
        .manager
        .peers
        .get_mut(&fixture.peer)
        .unwrap()
        .is_dynamic = true;
    fixture.manager.dynamic_peer_count = 1;
    let (lane_tx, mut lane) = mpsc::channel(2);
    fixture.manager.rib_tx = lane_tx.clone();
    match state {
        BarrierLane::Full => while lane_tx.try_send(barrier_filler()).is_ok() {},
        BarrierLane::DeferredAhead => {
            while lane_tx.try_send(barrier_filler()).is_ok() {}
            fixture
                .manager
                .defer_rib_update(None, barrier_filler())
                .unwrap();
            while lane.try_recv().is_ok() {}
            assert_eq!(fixture.manager.deferred_rib.queue.len(), 1);
            assert_eq!(lane_tx.capacity(), 2, "the lane itself has room");
        }
        BarrierLane::RoundSpent => {
            fixture
                .replace_idle(super::command_fan_out::wedged_session())
                .await;
        }
    }
    // Only the manager's own waits move the clock from here on.
    tokio::time::pause();
    let peer = fixture.peer.clone();
    let address = peer.address;
    let mut manager = fixture.manager;
    let retiring = tokio::spawn(async move {
        manager
            .handle_session_notification(SessionNotification::BackToIdle {
                peer_addr: address,
                session_id: 1,
                role: rustbgpd_transport::SessionRole::Primary,
            })
            .await;
        manager
    });
    BarrierFixture {
        retiring,
        lane,
        peer,
        rib_task: fixture.rib_task,
    }
}

/// The lane's next updates up to the fence acknowledgement, by kind, with a
/// deferred session end reported as the `PeerDown` it carries.
async fn receive_through_barrier(
    lane: &mut mpsc::Receiver<RibUpdate>,
) -> (Vec<&'static str>, oneshot::Sender<usize>) {
    let mut kinds = Vec::new();
    loop {
        match lane.recv().await.expect("the manager keeps its RIB lane") {
            RibUpdate::QueryLocRibCount { reply } => return (kinds, reply),
            RibUpdate::PeerDown { session_id: 1, .. } => kinds.push("PeerDown"),
            RibUpdate::LateSessionEnd(end)
                if matches!(*end, RibUpdate::PeerDown { session_id: 1, .. }) =>
            {
                kinds.push("PeerDown");
            }
            RibUpdate::ReleasePeer { .. } => kinds.push("filler"),
            _ => panic!("unexpected update on the retirement lane"),
        }
    }
}

/// A full mailbox, updates deferred ahead, or a session round that used its
/// whole window must not turn the retirement fence into a fail-stop: it is
/// queued behind what is already owed to the RIB, keeps its order (every
/// joined session's `PeerDown`, then the acknowledgement), and the dynamic
/// source is removed once the RIB answers, however long past the 500 ms
/// session round that is within the 5 s RIB bound.
async fn barrier_is_deferred_not_failed(state: BarrierLane) {
    let mut fixture = retire_dynamic_source(state).await;
    // The RIB resumes two seconds later: past the session round, inside
    // the fence's own bound.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !fixture.retiring.is_finished(),
        "{state:?}: the retirement waits for its fence"
    );
    let (kinds, acknowledge) = receive_through_barrier(&mut fixture.lane).await;
    let fence_from = kinds
        .iter()
        .position(|kind| *kind == "PeerDown")
        .unwrap_or_else(|| panic!("{state:?}: the joined session's PeerDown precedes the fence"));
    assert_eq!(
        kinds[fence_from..],
        ["PeerDown"],
        "{state:?}: nothing separates the session end from its acknowledgement"
    );
    assert!(
        kinds[..fence_from].iter().all(|kind| *kind == "filler"),
        "{state:?}: earlier updates keep their place ahead of the fence"
    );
    acknowledge.send(0).unwrap();
    let manager = fixture.retiring.await.unwrap();
    assert!(
        !manager.dampening_control_failed,
        "{state:?}: a busy RIB must not terminate the peer manager"
    );
    assert!(
        !manager.peers.contains_key(&fixture.peer),
        "{state:?}: the acknowledged fence found no block, so the source is removed"
    );
    assert_eq!(manager.dynamic_peer_count, 0);
    assert!(manager.deferred_rib.queue.is_empty());
    fixture.rib_task.abort();
}

#[tokio::test]
async fn dynamic_retirement_barrier_waits_out_a_full_rib_mailbox() {
    barrier_is_deferred_not_failed(BarrierLane::Full).await;
}

#[tokio::test]
async fn dynamic_retirement_barrier_queues_behind_deferred_rib_updates() {
    barrier_is_deferred_not_failed(BarrierLane::DeferredAhead).await;
}

#[tokio::test]
async fn dynamic_retirement_barrier_outlives_a_spent_session_round() {
    barrier_is_deferred_not_failed(BarrierLane::RoundSpent).await;
}

/// The fence is still bounded: a RIB that admits it and never answers within
/// `RIB_REPLY_TIMEOUT` leaves the retirement unacknowledged, which retains
/// the disabled recovery target and stops the peer manager, as before.
#[tokio::test]
async fn dynamic_retirement_barrier_unanswered_past_its_bound_still_fail_stops() {
    let mut fixture = retire_dynamic_source(BarrierLane::Full).await;
    let started = tokio::time::Instant::now();
    let (_, held_reply) = receive_through_barrier(&mut fixture.lane).await;
    let manager = fixture.retiring.await.unwrap();
    let waited = started.elapsed();
    assert!(
        waited >= RIB_REPLY_TIMEOUT && waited < RIB_REPLY_TIMEOUT + Duration::from_millis(2),
        "the fence waits out its own bound, no longer: {waited:?}"
    );
    assert!(manager.dampening_control_failed);
    assert!(!manager.peers[&fixture.peer].enabled);
    assert_eq!(manager.dynamic_peer_count, 1);
    drop(held_reply);
    fixture.rib_task.abort();
}
