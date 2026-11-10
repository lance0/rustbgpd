use super::evpn_group_storage::{fixture, received, stage};
use super::*;
use crate::test_support::peer_v4;
use crate::update::ExactExportKey;
use std::sync::atomic::{AtomicUsize, Ordering};

fn install_routes(manager: &mut RibManager, gid: usize, count: u8) -> Vec<EvpnRibRoute> {
    (1..=count)
        .map(|suffix| {
            let mut route = received(100);
            route.route = make_evpn_imet(Ipv4Addr::new(198, 51, 100, suffix), 1).route;
            assert_eq!(stage(manager, gid, &route).deltas.len(), 1);
            route
        })
        .collect()
}

#[test]
fn evpn_completeness_checkpoints_every_visited_row_and_preserves_refusal() {
    let (mut manager, _member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 7);
    let group = manager.group_ribs.get_mut(&gid).unwrap();
    assert!(group.evpn_projection_complete());
    let mut visits = 0;
    assert!(group.evpn_projection_complete_with_checkpoint(&mut || visits += 1));
    assert_eq!(visits, routes.len());

    let missing = make_evpn_imet(Ipv4Addr::new(198, 51, 100, 99), 1);
    group.table.remove_evpn(&routes[0].key());
    group.table.insert_evpn(missing.clone());
    // Cardinalities still match; the full-table lookup must reject the row
    // without received metadata and checkpoint that row before returning.
    let expected = group
        .table
        .iter_evpn()
        .position(|route| route.key() == missing.key())
        .unwrap()
        + 1;
    visits = 0;
    assert!(!group.evpn_projection_complete_with_checkpoint(&mut || visits += 1));
    assert_eq!(visits, expected);
}

#[test]
fn evpn_projection_checkpoints_wholly_excluded_rtc_source_and_rejection_rows() {
    let (mut manager, member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 7);
    let membership = RtcMembership::default();
    let rejected = routes
        .iter()
        .map(|route| ExactExportKey::Evpn(route.key()))
        .collect::<HashSet<_>>();
    for (target, rtc, overlay) in [
        (member, Some(&membership), None),
        (routes[0].peer, None, None),
        (member, None, Some(&rejected)),
    ] {
        let mut visits = 0;
        let yielded = manager.group_ribs[&gid]
            .evpn_member_projection_with_checkpoint(
                target,
                manager.cluster_id,
                rtc,
                overlay,
                || visits += 1,
            )
            .count();
        assert_eq!(yielded, 0);
        assert_eq!(visits, routes.len());
    }
}

#[test]
fn evpn_shared_empty_capture_checkpoints_completeness_count_and_population() {
    let (mut manager, member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 7);
    manager.peer_unexportable.insert(
        member,
        routes
            .iter()
            .map(|route| ExactExportKey::Evpn(route.key()))
            .collect(),
    );
    let visits = Arc::new(AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = visits.clone();
        move |seam| {
            if seam == "capture_evpn" {
                visits.fetch_add(1, Ordering::SeqCst);
            }
        }
    }));
    assert!(
        manager.with_replacement_readiness(|manager| manager.capture_shared_evpn_admitted(member))
    );
    assert_eq!(
        visits.load(Ordering::SeqCst),
        routes.len() * 2,
        "completeness and the single OLD projection walk each visit every excluded row"
    );
    let handle = manager.evpn_recovery_handle(member).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof_keys(handle).unwrap().unwrap(),
        [] as [rustbgpd_wire::EvpnRouteKey; 0]
    );
}

#[test]
fn evpn_private_capture_preserves_keys_and_checkpoints_projection_and_insertion() {
    let (mut manager, member, _gid, _output) = fixture();
    let routes: Vec<_> = (1..=7)
        .map(|suffix| make_evpn_imet(Ipv4Addr::new(198, 51, 100, suffix), 1))
        .collect();
    for route in &routes {
        manager
            .adj_ribs_out
            .get_mut(&member)
            .unwrap()
            .insert_evpn(route.clone());
    }
    let visits = Arc::new(AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = visits.clone();
        move |seam| {
            if seam == "capture_evpn" {
                visits.fetch_add(1, Ordering::SeqCst);
            }
        }
    }));
    assert!(
        manager.with_replacement_readiness(|manager| manager.capture_private_evpn_admitted(member))
    );
    assert_eq!(
        visits.load(Ordering::SeqCst),
        routes.len().div_ceil(64) + 4,
        "one checkpoint per 64 captured keys plus the slot-space and bitset allocation brackets"
    );
    let handle = manager.evpn_recovery_handle(member).unwrap();
    let proof: HashSet<_> = manager
        .evpn_recovery
        .proof_keys(handle)
        .unwrap()
        .unwrap()
        .iter()
        .copied()
        .collect();
    assert_eq!(proof, routes.iter().map(EvpnRibRoute::key).collect());
}

#[test]
fn evpn_denial_replacement_checkpoints_staged_and_inserted_rows() {
    let (mut manager, _member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 3);
    let group = manager.group_ribs.get_mut(&gid).unwrap();
    let old = (
        routes[0].peer,
        None,
        routes[0].extended_communities().to_vec(),
    );
    for route in &routes {
        group.evpn_policy_denied.insert(route.key(), old.clone());
    }
    let new = make_evpn_imet(Ipv4Addr::new(198, 51, 100, 99), 1);
    let replacement = (peer_v4(Ipv4Addr::new(192, 0, 2, 77)), None, Vec::new());
    let inserted = (peer_v4(Ipv4Addr::new(192, 0, 2, 88)), None, Vec::new());
    let keys = HashSet::from([routes[0].key(), routes[1].key()]);
    let mut visits = 0;
    group.replace_evpn_denials_with_checkpoint(
        &keys,
        [
            (routes[0].key(), replacement.clone()),
            (new.key(), inserted.clone()),
        ],
        &mut || visits += 1,
    );
    // One checkpoint per staged key and per inserted denial; untouched
    // retained rows are not visited.
    assert_eq!(visits, keys.len() + 2);
    assert_eq!(group.evpn_policy_denied.len(), 3);
    assert_eq!(group.evpn_policy_denied[&routes[0].key()], replacement);
    assert!(!group.evpn_policy_denied.contains_key(&routes[1].key()));
    assert_eq!(group.evpn_policy_denied[&routes[2].key()], old);
    assert_eq!(group.evpn_policy_denied[&new.key()], inserted);
}

#[test]
fn shared_capture_proof_iteration_checkpoints_once_per_slot_word() {
    let (mut manager, member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 32);
    manager.peer_unexportable.insert(
        member,
        routes[1..]
            .iter()
            .map(|route| ExactExportKey::Evpn(route.key()))
            .collect(),
    );
    assert!(manager.capture_shared_evpn_admitted(member));
    let handle = manager.evpn_recovery_handle(member).unwrap();
    let view = manager.evpn_recovery.proof(handle).unwrap().unwrap();
    let mut visits = 0;
    let keys = view
        .iter_with_checkpoint(|force| {
            assert!(!force);
            visits += 1;
        })
        .collect::<Vec<_>>();
    assert_eq!(keys, [routes[0].key()]);
    // One admitted key needs one 64-slot word step, not a walk of the table.
    assert!((1..=16).contains(&visits), "visits {visits}");
}

/// An owning group of `members` receivers holding `rows` EVPN routes, with
/// every writer full when `refused`, more readiness queries queued than any
/// pass can answer and a zero flush budget, so that every live service point
/// answers exactly one batch.
struct OwnedPass {
    manager: RibManager,
    gid: usize,
    peers: Vec<PeerId>,
    outputs: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    responses: Vec<oneshot::Receiver<Result<usize, crate::update::RibReadinessError>>>,
}

impl OwnedPass {
    fn new(members: u8, rows: u16, refused: bool) -> Self {
        let (mut manager, first, gid, output) = fixture();
        let mut outputs = vec![output];
        let mut peers = vec![first];
        for host in 0..members - 1 {
            let peer = PeerId::from_addr(Ipv4Addr::new(192, 0, 2, 40 + host).into());
            let (sender, mut output) = mpsc::channel(8);
            super::evpn_group_storage::register(&mut manager, peer, sender);
            while output.try_recv().is_ok() {}
            assert_eq!(manager.evpn_grouped_member_of(peer), Some(gid));
            assert!(manager.register_evpn_recovery(peer, false));
            outputs.push(output);
            peers.push(peer);
        }
        for index in 0..rows {
            let [high, low] = index.to_be_bytes();
            let mut route = received(100);
            route.route = make_evpn_imet(Ipv4Addr::new(198, 51, high, low), 1).route;
            assert_eq!(stage(&mut manager, gid, &route).deltas.len(), 1);
        }
        if refused {
            for peer in &peers {
                while manager.outbound_peers[peer]
                    .try_send(OutboundRouteUpdate::default())
                    .is_ok()
                {}
            }
        }
        let queued = (usize::from(members) * usize::from(rows) * 16 + 256)
            * crate::manager::QUERY_BUDGET_PER_CHUNK;
        let (readiness_tx, readiness_rx) = mpsc::channel(queued);
        manager.readiness_rx = Some(readiness_rx);
        let responses = (0..queued)
            .map(|_| {
                let (reply, response) = oneshot::channel();
                readiness_tx
                    .try_send(RibReadinessQuery::LocRibCount {
                        reply,
                        enqueued: Instant::now(),
                    })
                    .unwrap();
                response
            })
            .collect();
        manager.flush_poll_budget = Duration::ZERO;
        Self {
            manager,
            gid,
            peers,
            outputs,
            responses,
        }
    }

    /// One new Loc-RIB key for the pass to distribute.
    fn changed(&mut self) -> HashSet<rustbgpd_wire::EvpnRouteKey> {
        let changed = make_evpn_imet(Ipv4Addr::new(203, 0, 113, 1), 9);
        self.manager
            .loc_rib
            .recompute_evpn(changed.key(), [&changed].into_iter());
        HashSet::from([changed.key()])
    }

    /// Readiness batches answered since the last call; some queries must
    /// remain queued, or the count would understate the service points.
    fn batches(&mut self) -> usize {
        let mut answered = 0;
        for response in &mut self.responses {
            answered += usize::from(response.try_recv().is_ok());
        }
        assert!(answered < self.responses.len(), "the probe queue ran dry");
        assert_eq!(answered % crate::manager::QUERY_BUDGET_PER_CHUNK, 0);
        answered / crate::manager::QUERY_BUDGET_PER_CHUNK
    }
}

/// One inbound key staged into a group whose members all refuse it: every
/// member's recovery capture runs in this one actor turn, before the batch's
/// projection change. Returns the readiness batches answered during the pass
/// and the checkpoints (visited rows and ledger steps) the captures passed.
fn refused_owned_pass(members: u8, rows: u16) -> (usize, usize) {
    let mut pass = OwnedPass::new(members, rows, true);
    let keys = pass.changed();
    let gid = pass.gid;
    let work = super::work_scaling::checkpoints_in(|| {
        pass.manager.stage_group_evpn_keys(gid, &keys);
    });
    for peer in &pass.peers {
        let handle = pass.manager.evpn_recovery_handle(*peer).unwrap();
        assert!(
            !pass.manager.evpn_recovery.is_dormant(handle),
            "every refused member captured its table-sized proof"
        );
    }
    (pass.batches(), work["capture_evpn"])
}

/// A 150-member owned group ran fourteen refused members' captures back to
/// back in one turn and held the actor for 348 ms with no readiness service.
/// Ordinary ingest holds no readiness owner, so each capture must take the
/// lane itself: with a probe always waiting and no budget, every capture
/// checkpoint answers one batch, whatever the member count or table size.
/// The longest unserved stretch is then one checkpoint, not a pass.
#[test]
fn refused_owned_captures_serve_readiness_at_every_stride_for_any_size() {
    for (members, rows) in [(2, 64), (8, 64), (2, 512), (8, 512)] {
        let (batches, visited) = refused_owned_pass(members, rows);
        assert!(
            visited >= usize::from(members) * usize::from(rows),
            "{members} members x {rows} rows: the captures walked {visited} checkpoints"
        );
        assert!(
            batches >= visited,
            "{members} members x {rows} rows: {batches} readiness batches over {visited} \
             capture checkpoints leaves a stretch that grows with the pass"
        );
    }
}

/// The member loop of an owned pass is one commit per member. With every
/// writer open nothing is captured and no owner is taken, so each member
/// boundary must serve the lane itself: exactly one batch per member.
#[test]
fn owned_pass_serves_readiness_at_each_member_boundary() {
    for members in [1, 3, 8] {
        let mut pass = OwnedPass::new(members, 16, false);
        let keys = pass.changed();
        let peer = pass.peers[0];
        pass.manager
            .distribute_evpn_keys_to_peer(peer, &keys, &mut || {});
        assert!(pass.manager.dirty_peers.is_empty());
        assert_eq!(pass.batches(), usize::from(members), "{members} members");
    }
}

/// A member that retains a recovery proof with its writer open again gets a
/// complete feed: a completeness walk, a table walk with route clones, an
/// OLD proof walk and a table-sized commit. In ordinary ingest that is as
/// long as a capture and was just as unserved. The pass takes the lane, so
/// every member's feed build answers at least one batch per table row.
#[test]
fn retained_owned_feed_builds_serve_readiness_at_every_stride_for_any_size() {
    for (members, rows) in [(2_u8, 64_u16), (4, 64), (2, 256), (4, 256)] {
        let mut pass = OwnedPass::new(members, rows, true);
        let keys = pass.changed();
        let gid = pass.gid;
        pass.manager.stage_group_evpn_keys(gid, &keys);
        for output in &mut pass.outputs {
            while output.try_recv().is_ok() {}
        }
        pass.batches();
        let second = make_evpn_imet(Ipv4Addr::new(203, 0, 113, 2), 9);
        pass.manager
            .loc_rib
            .recompute_evpn(second.key(), [&second].into_iter());
        let peer = pass.peers[0];
        assert!(pass.manager.dirty_peers.is_empty());
        let builds = pass.manager.adj_rib_out_commit_stats.successful_enqueues;
        pass.manager
            .distribute_evpn_keys_to_peer(peer, &HashSet::from([second.key()]), &mut || {});
        assert_eq!(
            pass.manager.adj_rib_out_commit_stats.successful_enqueues - builds,
            usize::from(members),
            "every retained member's complete feed was built and admitted"
        );
        let batches = pass.batches();
        assert!(
            batches >= usize::from(members) * usize::from(rows),
            "{members} members x {rows} rows: {batches} readiness batches leaves a stretch \
             as long as one member's feed build"
        );
    }
}

/// A reply alone does not unblock a probe: the waiting task is woken on the
/// actor's own worker and cannot run while the pass holds it. The pass must
/// hand the executor off, so the probe task itself completes mid-pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_owned_pass_lets_the_waiting_probe_task_run() {
    let mut pass = OwnedPass::new(4, 64, true);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    pass.manager.readiness_rx = Some(readiness_rx);
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (reply, response) = oneshot::channel();
    readiness_tx
        .try_send(RibReadinessQuery::LocRibCount {
            reply,
            enqueued: Instant::now(),
        })
        .unwrap();
    let parked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = tokio::spawn({
        let completed = Arc::clone(&completed);
        let parked = Arc::clone(&parked);
        let mut response = response;
        async move {
            std::future::poll_fn(|cx| {
                let reply = std::pin::Pin::new(&mut response).poll(cx);
                // Its waker is registered: only a wake can resume it now.
                parked.store(reply.is_pending(), Ordering::SeqCst);
                reply
            })
            .await
            .unwrap()
            .unwrap();
            completed.store(true, Ordering::SeqCst);
        }
    });
    // The probe has polled its reply and found none. Then let that poll
    // return, so the task is parked rather than still running.
    while !parked.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let ran_during_pass = Arc::new(std::sync::atomic::AtomicBool::new(false));
    pass.manager.replacement_readiness_test_hook = Some(Arc::new({
        let completed = Arc::clone(&completed);
        let ran_during_pass = Arc::clone(&ran_during_pass);
        move |seam| {
            // The owner's last checkpoint: the reply went out at its first.
            if seam == "terminal_cleanup" && !ran_during_pass.load(Ordering::SeqCst) {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !completed.load(Ordering::SeqCst) && Instant::now() < deadline {
                    std::thread::yield_now();
                }
                ran_during_pass.store(completed.load(Ordering::SeqCst), Ordering::SeqCst);
            }
        }
    }));
    let keys = pass.changed();
    let gid = pass.gid;
    // The actor runs on a worker thread, where a reply wakes the probe onto
    // that worker's own queue; the test's main thread would hide that.
    tokio::spawn(async move {
        pass.manager.stage_group_evpn_keys(gid, &keys);
        drop(pass);
    })
    .await
    .unwrap();
    assert!(
        ran_during_pass.load(Ordering::SeqCst),
        "the probe task did not run until the pass returned"
    );
    probe.await.unwrap();
}

/// A member that is already dirty with a retained proof is skipped: its
/// capture returns at once and it gets no commit. Under the pass's owner the
/// boundary drain is inert and the caller's checkpoint was bound before the
/// owner existed, so the loop's own checkpoint must serve each such member.
#[test]
fn skipped_dirty_members_of_an_owned_pass_each_pass_a_live_checkpoint() {
    for members in [2_u8, 8] {
        let mut pass = OwnedPass::new(members, 16, true);
        let keys = pass.changed();
        let gid = pass.gid;
        pass.manager.stage_group_evpn_keys(gid, &keys);
        for peer in pass.peers.clone() {
            pass.manager.mark_outbound_dirty_inner(peer, false);
        }
        let second = make_evpn_imet(Ipv4Addr::new(203, 0, 113, 2), 9);
        pass.manager
            .loc_rib
            .recompute_evpn(second.key(), [&second].into_iter());
        let boundaries = Arc::new(AtomicUsize::new(0));
        pass.manager.replacement_readiness_test_hook = Some(Arc::new({
            let boundaries = Arc::clone(&boundaries);
            move |seam| {
                if seam == "selection_evpn" {
                    boundaries.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
        let peer = pass.peers[0];
        pass.manager
            .distribute_evpn_keys_to_peer(peer, &HashSet::from([second.key()]), &mut || {});
        pass.manager.replacement_readiness_test_hook = None;
        assert!(
            boundaries.load(Ordering::SeqCst) >= usize::from(members),
            "{members} skipped members passed {} live boundary checkpoints",
            boundaries.load(Ordering::SeqCst)
        );
    }
}
